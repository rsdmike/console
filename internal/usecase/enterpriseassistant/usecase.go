// Package enterpriseassistant is the Go port of the .NET Enterprise
// Assistant: it serves rpc-go's 802.1x / AMT TLS certificate flow against
// Active Directory and a Microsoft CA, and owns the EA settings.
package enterpriseassistant

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/device-management-toolkit/console/config"
	"github.com/device-management-toolkit/console/pkg/ea/ad"
	"github.com/device-management-toolkit/console/pkg/ea/adcs"
	"github.com/device-management-toolkit/console/pkg/logger"
)

// adTimeout bounds dialing AD and each LDAP operation.
const adTimeout = 15 * time.Second

var _ Feature = (*UseCase)(nil)

// UseCase implements Feature.
type UseCase struct {
	log        logger.Interface
	dialer     DirectoryDialer
	caFactory  CAFactory
	csrBuilder CSRBuilder
	store      SettingsStore
	now        func() time.Time

	mu       sync.RWMutex
	settings config.EA
	revision uint64

	rootMu  sync.Mutex
	rootRev uint64
	rootOK  bool
	rootDER []byte
}

// snapshot is an immutable copy of the settings and their revision.
type snapshot struct {
	ea  config.EA
	rev uint64
}

// New builds the use case from the settings currently in config.ConsoleConfig.EA.
func New(log logger.Interface, dialer DirectoryDialer, caFactory CAFactory, csrBuilder CSRBuilder, store SettingsStore) *UseCase {
	var initial config.EA
	if config.ConsoleConfig != nil {
		initial = config.ConsoleConfig.EA
	}

	return newWithSettings(log, dialer, caFactory, csrBuilder, store, initial)
}

func newWithSettings(log logger.Interface, dialer DirectoryDialer, caFactory CAFactory, csrBuilder CSRBuilder, store SettingsStore, initial config.EA) *UseCase {
	initial = cloneEA(initial)

	return &UseCase{
		log:        log,
		dialer:     dialer,
		caFactory:  caFactory,
		csrBuilder: csrBuilder,
		store:      store,
		now:        time.Now,
		settings:   initial,
		revision:   1,
	}
}

// NewConfigStore persists settings to config.yml and mirrors them into
// config.ConsoleConfig.EA.
func NewConfigStore() SettingsStore { return configStore{} }

type configStore struct{}

func (configStore) Save(settings config.EA) error {
	if err := config.SaveEASettings(settings); err != nil {
		return fmt.Errorf("enterpriseassistant.Save: %w", err)
	}

	if config.ConsoleConfig != nil {
		config.ConsoleConfig.EA = cloneEA(settings)
	}

	return nil
}

func cloneEA(in config.EA) config.EA {
	out := in
	out.AD.SecurityGroups = slices.Clone(in.AD.SecurityGroups)
	out.CA.AltNames = slices.Clone(in.CA.AltNames)

	return out
}

func (uc *UseCase) snapshot() snapshot {
	uc.mu.RLock()
	defer uc.mu.RUnlock()

	return snapshot{ea: cloneEA(uc.settings), rev: uc.revision}
}

// DeviceAccess returns the /ea switch and the rpc-go credentials.
func (uc *UseCase) DeviceAccess() DeviceAccess {
	uc.mu.RLock()
	defer uc.mu.RUnlock()

	return DeviceAccess{Enabled: uc.settings.Enabled, Username: uc.settings.Username, Password: uc.settings.Password}
}

func adConfigured(s *config.EA) bool {
	return s.AD.Domain != "" && s.AD.BindUsername != "" && s.AD.BindPassword != ""
}

func caConfigured(s *config.EA) bool {
	return s.CA.Host != "" && s.CA.Name != ""
}

func adConfig(s *config.EA) ad.Config {
	return ad.Config{
		Domain:             s.AD.Domain,
		Server:             s.AD.Server,
		BindUsername:       s.AD.BindUsername,
		BindPassword:       s.AD.BindPassword,
		InsecureSkipVerify: s.AD.InsecureSkipVerify,
		Timeout:            adTimeout,
	}
}

func caConfig(s *config.EA) adcs.Config {
	return adcs.Config{
		Host:     s.CA.Host,
		CAName:   s.CA.Name,
		Domain:   s.AD.Domain,
		Username: s.AD.BindUsername,
		Password: s.AD.BindPassword,
	}
}

// dial opens AD with s; the caller closes the Directory.
func (uc *UseCase) dial(ctx context.Context, s *config.EA) (Directory, error) {
	if !adConfigured(s) {
		return nil, errADNotConfigured
	}

	dir, err := uc.dialer(ctx, adConfig(s))
	if err != nil {
		return nil, upstream("active directory", err)
	}

	return dir, nil
}

func (uc *UseCase) closeDir(dir Directory) {
	if err := dir.Close(); err != nil {
		uc.log.Warn(fmt.Sprintf("enterpriseassistant: closing active directory session: %v", err))
	}
}

// rootCert returns the configured CA's certificate (DER) as published in AD,
// or nil when no CA name is set or AD does not list it. Found certificates
// are cached until the settings change.
func (uc *UseCase) rootCert(ctx context.Context, dir Directory, s snapshot) ([]byte, error) {
	if s.ea.CA.Name == "" {
		return nil, nil
	}

	uc.rootMu.Lock()
	if uc.rootOK && uc.rootRev == s.rev {
		der := uc.rootDER
		uc.rootMu.Unlock()

		return der, nil
	}
	uc.rootMu.Unlock()

	cas, err := dir.CertificateAuthorities(ctx)
	if err != nil {
		return nil, upstream("active directory: list certificate authorities", err)
	}

	for _, ca := range cas {
		if strings.EqualFold(ca.Name, s.ea.CA.Name) && len(ca.Certificate) > 0 {
			uc.rootMu.Lock()
			uc.rootRev, uc.rootOK, uc.rootDER = s.rev, true, bytes.Clone(ca.Certificate)
			uc.rootMu.Unlock()

			return ca.Certificate, nil
		}
	}

	uc.log.Warn(fmt.Sprintf("enterpriseassistant: certificate authority %q not found in active directory", s.ea.CA.Name))

	return nil, nil
}

// parseRoot parses the CA certificate, nil when absent or malformed.
func parseRoot(der []byte) *x509.Certificate {
	if len(der) == 0 {
		return nil
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}

	return cert
}
