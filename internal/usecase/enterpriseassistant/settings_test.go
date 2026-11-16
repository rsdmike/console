package enterpriseassistant

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/device-management-toolkit/console/config"
	dto "github.com/device-management-toolkit/console/internal/entity/dto/v2"
	"github.com/device-management-toolkit/console/pkg/ea/ad"
	"github.com/device-management-toolkit/console/pkg/ea/adcs"
)

func TestGetSettingsHidesPasswords(t *testing.T) {
	t.Parallel()

	h := newHarness(t, fullSettings())
	got := h.uc.GetSettings(context.Background())

	require.Empty(t, got.Password)
	require.Empty(t, got.ActiveDirectory.BindPassword)
	require.True(t, got.PasswordSet)
	require.True(t, got.ActiveDirectory.BindPasswordSet)
	require.Equal(t, "eauser", got.Username)
	require.Equal(t, "vprodemo-CA", got.CertificateAuthority.Name)

	raw, err := json.Marshal(got)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "eapass")
	require.NotContains(t, string(raw), "bindpass")

	empty := newHarness(t, config.EA{}).uc.GetSettings(context.Background())
	require.False(t, empty.PasswordSet)
	require.False(t, empty.ActiveDirectory.BindPasswordSet)
	require.NotNil(t, empty.ActiveDirectory.SecurityGroups, "lists serialize as [] not null")
	require.NotNil(t, empty.CertificateAuthority.AltNames)
}

func validInput() dto.EASettings {
	s := fullSettings()
	in := toDTO(&s)
	in.Password = "newpass"
	in.ActiveDirectory.BindPassword = "newbind"

	return in
}

func TestUpdateSettingsValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		stored config.EA
		mutate func(in *dto.EASettings)
		want   string
	}{
		{
			"bad deviceNameType", fullSettings(), func(in *dto.EASettings) { in.DeviceNameType = "fqdn" },
			"enterprise assistant: deviceNameType must be hostname or nodeid",
		},
		{
			"empty deviceNameType", fullSettings(), func(in *dto.EASettings) { in.DeviceNameType = "" },
			"enterprise assistant: deviceNameType must be hostname or nodeid",
		},
		{
			"bad commonName", fullSettings(), func(in *dto.EASettings) { in.CertificateAuthority.CommonName = "email" },
			"enterprise assistant: certificateAuthority.commonName must be one of distinguishedname, dnsfqdn, hostname, userprincipalname, samaccountname, uuid",
		},
		{
			"bad altName", fullSettings(), func(in *dto.EASettings) { in.CertificateAuthority.AltNames = []string{"dnsfqdn", "ip"} },
			`enterprise assistant: certificateAuthority.altNames: "ip" must be one of distinguishedname, dnsfqdn, hostname, userprincipalname, samaccountname, uuid`,
		},
		{
			"enabled without username", fullSettings(), func(in *dto.EASettings) { in.Username = "" },
			"enterprise assistant: required when enabled: username",
		},
		{"enabled without AD fields", fullSettings(), func(in *dto.EASettings) {
			in.ActiveDirectory.Domain = ""
			in.ActiveDirectory.BindUsername = " "
		}, "enterprise assistant: required when enabled: activeDirectory.domain, activeDirectory.bindUsername"},
		{
			"enabled without any bind password",
			config.EA{},
			func(in *dto.EASettings) { in.ActiveDirectory.BindPassword = "" },
			"enterprise assistant: required when enabled: activeDirectory.bindPassword",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, tt.stored)
			in := validInput()
			tt.mutate(&in)

			_, err := h.uc.UpdateSettings(context.Background(), in)
			require.ErrorIs(t, err, ErrValidation)
			require.EqualError(t, err, tt.want)
			require.Empty(t, h.store.saved)
			require.Equal(t, uint64(1), h.uc.snapshot().rev)
		})
	}
}

func TestUpdateSettings(t *testing.T) {
	t.Parallel()

	t.Run("empty passwords keep the stored ones", func(t *testing.T) {
		t.Parallel()

		h := newHarness(t, fullSettings())
		in := validInput()
		in.Password, in.ActiveDirectory.BindPassword = "", ""
		in.ActiveDirectory.ComputerOU = "OU=AMT,OU=Devices"

		got, err := h.uc.UpdateSettings(context.Background(), in)
		require.NoError(t, err)
		require.True(t, got.PasswordSet)
		require.Empty(t, got.Password)
		require.Equal(t, "OU=AMT,OU=Devices", got.ActiveDirectory.ComputerOU)

		require.Len(t, h.store.saved, 1)
		require.Equal(t, "eapass", h.store.saved[0].Password)
		require.Equal(t, "bindpass", h.store.saved[0].AD.BindPassword)
		require.Equal(t, DeviceAccess{Enabled: true, Username: "eauser", Password: "eapass"}, h.uc.DeviceAccess())
		require.Equal(t, uint64(2), h.uc.snapshot().rev)
	})

	t.Run("new passwords replace the stored ones, vocabulary is case-insensitive", func(t *testing.T) {
		t.Parallel()

		h := newHarness(t, fullSettings())
		in := validInput()
		in.DeviceNameType = "NodeID"
		in.CertificateAuthority.CommonName = "DNSFQDN"

		got, err := h.uc.UpdateSettings(context.Background(), in)
		require.NoError(t, err)
		require.Equal(t, "nodeid", got.DeviceNameType)
		require.Equal(t, "dnsfqdn", got.CertificateAuthority.CommonName)
		require.Equal(t, "newpass", h.store.saved[0].Password)
		require.Equal(t, "newbind", h.store.saved[0].AD.BindPassword)
		require.Equal(t, "newpass", h.uc.DeviceAccess().Password)
	})

	t.Run("disabled settings need no credentials", func(t *testing.T) {
		t.Parallel()

		h := newHarness(t, config.EA{})
		in := dto.EASettings{DeviceNameType: "hostname", CertificateAuthority: dto.EACertificateAuthority{CommonName: "dnsfqdn"}}

		_, err := h.uc.UpdateSettings(context.Background(), in)
		require.NoError(t, err)
		require.False(t, h.uc.DeviceAccess().Enabled)
	})

	t.Run("store failure keeps the old settings", func(t *testing.T) {
		t.Parallel()

		h := newHarness(t, fullSettings())
		h.store.err = errBoom

		_, err := h.uc.UpdateSettings(context.Background(), validInput())
		require.ErrorIs(t, err, errBoom)
		require.NotErrorIs(t, err, ErrValidation)
		require.Equal(t, "eapass", h.uc.DeviceAccess().Password)
		require.Equal(t, uint64(1), h.uc.snapshot().rev)
	})
}

func TestTestSettings(t *testing.T) {
	t.Parallel()

	noAD := fullSettings()
	noAD.AD.BindPassword = ""

	noCAHost := fullSettings()
	noCAHost.CA.Host = ""

	notConfigured := dto.EACheck{Message: "not configured"}
	bound := dto.EACheck{OK: true, Message: "Bound to dc1.vprodemo.com as svc-ea@vprodemo.com (DC=vprodemo,DC=com)"}

	tests := []struct {
		name     string
		stored   config.EA
		in       *dto.EASettings
		setup    func(h *harness)
		want     dto.EATestResult
		wantDial *ad.Config
	}{
		{"AD not configured", noAD, nil, nil, dto.EATestResult{ActiveDirectory: notConfigured, CertificateAuthority: notConfigured}, nil},
		{
			"AD bind fails, CA skipped", fullSettings(), nil, func(h *harness) { h.dialErr = errBoom },
			dto.EATestResult{ActiveDirectory: dto.EACheck{Message: "boom"}, CertificateAuthority: notConfigured},
			nil,
		},
		{"AD ok, no CA host", noCAHost, nil, nil, dto.EATestResult{ActiveDirectory: bound, CertificateAuthority: notConfigured}, nil},
		{
			"AD ok, CA ping fails", fullSettings(), nil, func(h *harness) { h.ca.pingErr = errBoom },
			dto.EATestResult{ActiveDirectory: bound, CertificateAuthority: dto.EACheck{Message: "boom"}},
			nil,
		},
		{"AD ok, CA ok", fullSettings(), nil, nil, dto.EATestResult{
			ActiveDirectory: bound, CertificateAuthority: dto.EACheck{OK: true, Message: "Connected to ca1.vprodemo.com (vprodemo-CA)"},
		}, nil},
		{"body overrides stored, empty bind password kept", fullSettings(), func() *dto.EASettings {
			in := validInput()
			in.ActiveDirectory.Server = "dc2.vprodemo.com"
			in.ActiveDirectory.BindPassword = ""
			in.CertificateAuthority.Host = ""

			return &in
		}(), nil, dto.EATestResult{ActiveDirectory: bound, CertificateAuthority: notConfigured}, &ad.Config{
			Domain: "vprodemo.com", Server: "dc2.vprodemo.com", BindUsername: "svc-ea@vprodemo.com", BindPassword: "bindpass", Timeout: adTimeout,
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, tt.stored)
			if tt.setup != nil {
				tt.setup(h)
			}

			got, err := h.uc.TestSettings(context.Background(), tt.in)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)

			if tt.wantDial != nil {
				require.Equal(t, []ad.Config{*tt.wantDial}, h.dialCfgs)
			}

			if got.ActiveDirectory.OK {
				require.Equal(t, 1, h.dir.closed)
			}

			require.Empty(t, h.store.saved, "test never persists")
		})
	}

	t.Run("invalid body is a validation error", func(t *testing.T) {
		t.Parallel()

		h := newHarness(t, fullSettings())
		in := validInput()
		in.DeviceNameType = "x"

		_, err := h.uc.TestSettings(context.Background(), &in)
		require.ErrorIs(t, err, ErrValidation)
	})
}

func TestDirectoryLists(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		h := newHarness(t, fullSettings())
		h.dir.containers = []string{"CN=Computers", "OU=AMT,OU=Devices"}
		h.dir.groups = []string{"CN=AMT Devices,CN=Users,DC=vprodemo,DC=com"}
		h.dir.cas = []ad.CertificateAuthority{{Name: "vprodemo-CA", Host: "ca1.vprodemo.com", Templates: []string{"AMT8021X", "WebServer"}, Certificate: []byte{1}}}

		containers, err := h.uc.Containers(context.Background())
		require.NoError(t, err)
		require.Equal(t, h.dir.containers, containers)

		groups, err := h.uc.SecurityGroups(context.Background())
		require.NoError(t, err)
		require.Equal(t, h.dir.groups, groups)

		cas, err := h.uc.Authorities(context.Background())
		require.NoError(t, err)
		require.Equal(t, []dto.EAAuthority{{Name: "vprodemo-CA", Host: "ca1.vprodemo.com", Templates: []string{"AMT8021X", "WebServer"}}}, cas)

		require.Equal(t, 3, h.dir.closed)
	})

	t.Run("empty lists are not nil", func(t *testing.T) {
		t.Parallel()

		h := newHarness(t, fullSettings())
		h.dir.cas = []ad.CertificateAuthority{{Name: "x"}}

		containers, err := h.uc.Containers(context.Background())
		require.NoError(t, err)
		require.NotNil(t, containers)

		cas, err := h.uc.Authorities(context.Background())
		require.NoError(t, err)
		require.NotNil(t, cas[0].Templates)
	})

	calls := map[string]func(uc *UseCase) error{
		"containers": func(uc *UseCase) error {
			_, err := uc.Containers(context.Background())

			return err
		},
		"groups": func(uc *UseCase) error {
			_, err := uc.SecurityGroups(context.Background())

			return err
		},
		"authorities": func(uc *UseCase) error {
			_, err := uc.Authorities(context.Background())

			return err
		},
	}

	for name, call := range calls {
		t.Run(name+" not configured", func(t *testing.T) {
			t.Parallel()

			s := fullSettings()
			s.AD.Domain = ""
			err := call(newHarness(t, s).uc)
			require.ErrorIs(t, err, ErrNotConfigured)
			require.EqualError(t, err, "enterprise assistant: active directory is not configured")
		})

		t.Run(name+" upstream failure", func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, fullSettings())
			h.dir.listErr = errBoom
			h.dir.casErr = errBoom

			require.ErrorIs(t, call(h.uc), ErrUpstream)
		})

		t.Run(name+" dial failure", func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, fullSettings())
			h.dialErr = errBoom

			require.ErrorIs(t, call(h.uc), ErrUpstream)
		})
	}
}

func TestCAConfigUsesBindAccount(t *testing.T) {
	t.Parallel()

	s := fullSettings()
	require.Equal(t, adcs.Config{
		Host: "ca1.vprodemo.com", CAName: "vprodemo-CA", Domain: "vprodemo.com", Username: "svc-ea@vprodemo.com", Password: "bindpass",
	}, caConfig(&s))
}
