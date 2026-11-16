package enterpriseassistant

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/device-management-toolkit/console/config"
	dto "github.com/device-management-toolkit/console/internal/entity/dto/v2"
)

const msgNotConfigured = "not configured"

func toDTO(s *config.EA) dto.EASettings {
	return dto.EASettings{
		Enabled:        s.Enabled,
		URL:            s.URL,
		Username:       s.Username,
		PasswordSet:    s.Password != "",
		DeviceNameType: s.DeviceNameType,
		ActiveDirectory: dto.EAActiveDirectory{
			Domain:             s.AD.Domain,
			Server:             s.AD.Server,
			BindUsername:       s.AD.BindUsername,
			BindPasswordSet:    s.AD.BindPassword != "",
			ComputerOU:         s.AD.ComputerOU,
			SecurityGroups:     nonNil(s.AD.SecurityGroups),
			InsecureSkipVerify: s.AD.InsecureSkipVerify,
		},
		CertificateAuthority: dto.EACertificateAuthority{
			Host:       s.CA.Host,
			Name:       s.CA.Name,
			Template:   s.CA.Template,
			CommonName: s.CA.CommonName,
			AltNames:   nonNil(s.CA.AltNames),
		},
	}
}

func nonNil(in []string) []string {
	if in == nil {
		return []string{}
	}

	return slices.Clone(in)
}

func lowerAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		out = append(out, strings.ToLower(strings.TrimSpace(v)))
	}

	return out
}

// merge applies in onto stored; empty passwords keep the stored ones.
func merge(stored *config.EA, in *dto.EASettings) config.EA {
	out := config.EA{
		Enabled:        in.Enabled,
		URL:            strings.TrimSpace(in.URL),
		Username:       in.Username,
		Password:       in.Password,
		DeviceNameType: strings.ToLower(strings.TrimSpace(in.DeviceNameType)),
		AD: config.EAActiveDirectory{
			Domain:             strings.TrimSpace(in.ActiveDirectory.Domain),
			Server:             strings.TrimSpace(in.ActiveDirectory.Server),
			BindUsername:       in.ActiveDirectory.BindUsername,
			BindPassword:       in.ActiveDirectory.BindPassword,
			ComputerOU:         strings.TrimSpace(in.ActiveDirectory.ComputerOU),
			SecurityGroups:     slices.Clone(in.ActiveDirectory.SecurityGroups),
			InsecureSkipVerify: in.ActiveDirectory.InsecureSkipVerify,
		},
		CA: config.EACertificateAuthority{
			Host:       strings.TrimSpace(in.CertificateAuthority.Host),
			Name:       strings.TrimSpace(in.CertificateAuthority.Name),
			Template:   strings.TrimSpace(in.CertificateAuthority.Template),
			CommonName: strings.ToLower(strings.TrimSpace(in.CertificateAuthority.CommonName)),
			AltNames:   lowerAll(in.CertificateAuthority.AltNames),
		},
	}

	if out.Password == "" {
		out.Password = stored.Password
	}

	if out.AD.BindPassword == "" {
		out.AD.BindPassword = stored.AD.BindPassword
	}

	return out
}

// validateVocabulary checks the enumerated fields.
func validateVocabulary(s *config.EA) error {
	if s.DeviceNameType != deviceNameHostname && s.DeviceNameType != deviceNameNodeID {
		return validationError("enterprise assistant: deviceNameType must be hostname or nodeid")
	}

	if !slices.Contains(nameKinds, s.CA.CommonName) {
		return validationError("enterprise assistant: certificateAuthority.commonName must be one of " + strings.Join(nameKinds, ", "))
	}

	for _, n := range s.CA.AltNames {
		if !slices.Contains(nameKinds, n) {
			return validationError(fmt.Sprintf("enterprise assistant: certificateAuthority.altNames: %q must be one of %s", n, strings.Join(nameKinds, ", ")))
		}
	}

	return nil
}

// validateSettings adds the rules that apply when the feature is enabled.
func validateSettings(s *config.EA) error {
	if err := validateVocabulary(s); err != nil {
		return err
	}

	if !s.Enabled {
		return nil
	}

	var missing []string

	for _, f := range []struct {
		name  string
		value string
	}{
		{"username", s.Username},
		{"activeDirectory.domain", s.AD.Domain},
		{"activeDirectory.bindUsername", s.AD.BindUsername},
		{"activeDirectory.bindPassword", s.AD.BindPassword},
	} {
		if strings.TrimSpace(f.value) == "" {
			missing = append(missing, f.name)
		}
	}

	if len(missing) > 0 {
		return validationError("enterprise assistant: required when enabled: " + strings.Join(missing, ", "))
	}

	return nil
}

// GetSettings returns the settings without any password.
func (uc *UseCase) GetSettings(_ context.Context) dto.EASettings {
	s := uc.snapshot()

	return toDTO(&s.ea)
}

// UpdateSettings validates, persists and applies new settings.
func (uc *UseCase) UpdateSettings(_ context.Context, in dto.EASettings) (dto.EASettings, error) {
	uc.mu.Lock()
	defer uc.mu.Unlock()

	next := merge(&uc.settings, &in)
	if err := validateSettings(&next); err != nil {
		return dto.EASettings{}, err
	}

	if err := uc.store.Save(cloneEA(next)); err != nil {
		return dto.EASettings{}, fmt.Errorf("enterpriseassistant.UpdateSettings: %w", err)
	}

	uc.settings = next
	uc.revision++

	uc.log.Info("enterpriseassistant: settings updated")

	return toDTO(&next), nil
}

// TestSettings checks AD (dial and bind) and, when AD bound and a CA host is
// set, the CA (Ping). nil tests the stored settings.
func (uc *UseCase) TestSettings(ctx context.Context, in *dto.EASettings) (dto.EATestResult, error) {
	s := uc.snapshot().ea

	if in != nil {
		s = merge(&s, in)
		if err := validateVocabulary(&s); err != nil {
			return dto.EATestResult{}, err
		}
	}

	result := dto.EATestResult{
		ActiveDirectory:      dto.EACheck{Message: msgNotConfigured},
		CertificateAuthority: dto.EACheck{Message: msgNotConfigured},
	}

	if !adConfigured(&s) {
		return result, nil
	}

	dir, err := uc.dialer(ctx, adConfig(&s))
	if err != nil {
		result.ActiveDirectory.Message = err.Error()

		return result, nil
	}

	result.ActiveDirectory = dto.EACheck{
		OK:      true,
		Message: fmt.Sprintf("Bound to %s as %s (%s)", dir.ServerName(), s.AD.BindUsername, dir.BaseDN()),
	}

	uc.closeDir(dir)

	if s.CA.Host == "" {
		return result, nil
	}

	if err := uc.caFactory(caConfig(&s)).Ping(ctx); err != nil {
		result.CertificateAuthority.Message = err.Error()

		return result, nil
	}

	result.CertificateAuthority = dto.EACheck{OK: true, Message: fmt.Sprintf("Connected to %s (%s)", s.CA.Host, s.CA.Name)}

	return result, nil
}

// withDirectory dials AD with the stored settings, runs fn and closes.
func withDirectory[T any](ctx context.Context, uc *UseCase, op string, fn func(Directory) (T, error)) (T, error) {
	var zero T

	s := uc.snapshot()

	dir, err := uc.dial(ctx, &s.ea)
	if err != nil {
		return zero, err
	}
	defer uc.closeDir(dir)

	v, err := fn(dir)
	if err != nil {
		return zero, upstream("active directory: "+op, err)
	}

	return v, nil
}

// Containers lists OUs and containers relative to the base DN.
func (uc *UseCase) Containers(ctx context.Context) ([]string, error) {
	return withDirectory(ctx, uc, "list containers", func(d Directory) ([]string, error) {
		v, err := d.Containers(ctx)

		return nonNil(v), err
	})
}

// SecurityGroups lists security group DNs.
func (uc *UseCase) SecurityGroups(ctx context.Context) ([]string, error) {
	return withDirectory(ctx, uc, "list security groups", func(d Directory) ([]string, error) {
		v, err := d.SecurityGroups(ctx)

		return nonNil(v), err
	})
}

// Authorities lists the enterprise CAs published in AD.
func (uc *UseCase) Authorities(ctx context.Context) ([]dto.EAAuthority, error) {
	return withDirectory(ctx, uc, "list certificate authorities", func(d Directory) ([]dto.EAAuthority, error) {
		cas, err := d.CertificateAuthorities(ctx)
		if err != nil {
			return nil, err
		}

		out := make([]dto.EAAuthority, 0, len(cas))
		for _, ca := range cas {
			out = append(out, dto.EAAuthority{Name: ca.Name, Host: ca.Host, Templates: nonNil(ca.Templates)})
		}

		return out, nil
	})
}
