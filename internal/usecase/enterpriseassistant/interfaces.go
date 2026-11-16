package enterpriseassistant

import (
	"context"
	"time"

	"github.com/device-management-toolkit/console/config"
	dto "github.com/device-management-toolkit/console/internal/entity/dto/v2"
	"github.com/device-management-toolkit/console/pkg/ea/ad"
	"github.com/device-management-toolkit/console/pkg/ea/adcs"
	"github.com/device-management-toolkit/console/pkg/ea/csr"
)

// Directory is a bound Active Directory session (implemented by *ad.Client).
type Directory interface {
	Close() error
	DomainName() string
	BaseDN() string
	ServerName() string
	EnsureComputer(ctx context.Context, req ad.ComputerRequest) (ad.Computer, error)
	RemoveComputer(ctx context.Context, name, ou string) (bool, error)
	Containers(ctx context.Context) ([]string, error)
	SecurityGroups(ctx context.Context) ([]string, error)
	CertificateAuthorities(ctx context.Context) ([]ad.CertificateAuthority, error)
}

// CertificateAuthority is a Microsoft CA client (implemented by *adcs.Client).
type CertificateAuthority interface {
	Ping(ctx context.Context) error
	Submit(ctx context.Context, csrDER []byte, template string) (adcs.Result, error)
	Revoke(ctx context.Context, serialHex string, reason int, when time.Time) error
}

// DirectoryDialer opens a Directory session. It must return a nil interface
// (not a typed nil) on error.
type DirectoryDialer func(ctx context.Context, cfg ad.Config) (Directory, error)

// CAFactory builds a CA client.
type CAFactory func(cfg adcs.Config) CertificateAuthority

// CSRBuilder builds the null-signed PKCS#10 AMT signs.
type CSRBuilder func(req csr.Request) ([]byte, error)

// SettingsStore persists the ea settings section.
type SettingsStore interface {
	Save(settings config.EA) error
}

// DeviceAccess is what the /ea controller needs to authenticate rpc-go.
type DeviceAccess struct {
	Enabled  bool
	Username string
	Password string
}

// Feature is the Enterprise Assistant use case as the controllers see it.
type Feature interface {
	// DeviceAccess returns the current /ea switch and credentials.
	DeviceAccess() DeviceAccess

	// Profile, KeyPair, CSR and Remove serve the rpc-go device flow.
	Profile(ctx context.Context, req dto.EADeviceRequest) (dto.EADeviceResponse, error)
	KeyPair(ctx context.Context, req dto.EADeviceRequest) (dto.EADeviceResponse, error)
	CSR(ctx context.Context, req dto.EADeviceRequest) (dto.EADeviceResponse, error)
	Remove(ctx context.Context, req dto.EADeviceRequest) (dto.EARemoveResult, error)

	// Settings API used by sample-web-ui.
	GetSettings(ctx context.Context) dto.EASettings
	UpdateSettings(ctx context.Context, in dto.EASettings) (dto.EASettings, error)
	TestSettings(ctx context.Context, in *dto.EASettings) (dto.EATestResult, error)
	Containers(ctx context.Context) ([]string, error)
	SecurityGroups(ctx context.Context) ([]string, error)
	Authorities(ctx context.Context) ([]dto.EAAuthority, error)
}
