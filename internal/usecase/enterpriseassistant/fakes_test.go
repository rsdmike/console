package enterpriseassistant

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/device-management-toolkit/console/config"
	"github.com/device-management-toolkit/console/pkg/ea/ad"
	"github.com/device-management-toolkit/console/pkg/ea/adcs"
	"github.com/device-management-toolkit/console/pkg/ea/csr"
	"github.com/device-management-toolkit/console/pkg/logger"
)

// fakeDirectory is a hand-written Directory.
type fakeDirectory struct {
	mu sync.Mutex

	computer   ad.Computer
	ensureErr  error
	ensureReqs []ad.ComputerRequest

	removed    bool
	removeErr  error
	removeArgs [][2]string

	containers []string
	groups     []string
	listErr    error

	cas      []ad.CertificateAuthority
	casErr   error
	casCalls int

	closed int
}

func (d *fakeDirectory) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.closed++

	return nil
}

func (d *fakeDirectory) DomainName() string { return "vprodemo.com" }
func (d *fakeDirectory) BaseDN() string     { return "DC=vprodemo,DC=com" }
func (d *fakeDirectory) ServerName() string { return "dc1.vprodemo.com" }

func (d *fakeDirectory) EnsureComputer(_ context.Context, req ad.ComputerRequest) (ad.Computer, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.ensureReqs = append(d.ensureReqs, req)

	return d.computer, d.ensureErr
}

func (d *fakeDirectory) RemoveComputer(_ context.Context, name, ou string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.removeArgs = append(d.removeArgs, [2]string{name, ou})

	return d.removed, d.removeErr
}

func (d *fakeDirectory) Containers(_ context.Context) ([]string, error) {
	return d.containers, d.listErr
}

func (d *fakeDirectory) SecurityGroups(_ context.Context) ([]string, error) {
	return d.groups, d.listErr
}

func (d *fakeDirectory) CertificateAuthorities(_ context.Context) ([]ad.CertificateAuthority, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.casCalls++

	return d.cas, d.casErr
}

// fakeCA is a hand-written CertificateAuthority.
type fakeCA struct {
	mu sync.Mutex

	pingErr   error
	submitErr error
	revokeErr error
	result    adcs.Result

	submits   [][]byte
	templates []string
	revokes   []string
	reasons   []int
}

func (c *fakeCA) Ping(_ context.Context) error { return c.pingErr }

func (c *fakeCA) Submit(_ context.Context, der []byte, template string) (adcs.Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.submits = append(c.submits, der)
	c.templates = append(c.templates, template)

	return c.result, c.submitErr
}

func (c *fakeCA) Revoke(_ context.Context, serial string, reason int, _ time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.revokes = append(c.revokes, serial)
	c.reasons = append(c.reasons, reason)

	return c.revokeErr
}

type fakeStore struct {
	saved []config.EA
	err   error
}

func (s *fakeStore) Save(ea config.EA) error {
	if s.err != nil {
		return s.err
	}

	s.saved = append(s.saved, ea)

	return nil
}

// harness wires a UseCase to fakes.
type harness struct {
	uc    *UseCase
	dir   *fakeDirectory
	ca    *fakeCA
	store *fakeStore

	dialErr  error
	dialCfgs []ad.Config
	caCfgs   []adcs.Config
	csrReqs  []csr.Request
	csrOut   []byte
	csrErr   error
}

var testNow = time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)

func newHarness(t *testing.T, settings config.EA) *harness {
	t.Helper()

	h := &harness{
		dir:    &fakeDirectory{computer: testComputer()},
		ca:     &fakeCA{},
		store:  &fakeStore{},
		csrOut: []byte{0x30, 0x82, 0x01, 0x00},
	}

	dialer := func(_ context.Context, c ad.Config) (Directory, error) {
		h.dialCfgs = append(h.dialCfgs, c)
		if h.dialErr != nil {
			return nil, h.dialErr
		}

		return h.dir, nil
	}
	factory := func(c adcs.Config) CertificateAuthority {
		h.caCfgs = append(h.caCfgs, c)

		return h.ca
	}
	builder := func(r csr.Request) ([]byte, error) {
		h.csrReqs = append(h.csrReqs, r)

		return h.csrOut, h.csrErr
	}

	h.uc = newWithSettings(logger.New("error"), dialer, factory, builder, h.store, settings)
	h.uc.now = func() time.Time { return testNow }

	return h
}

func testComputer() ad.Computer {
	return ad.Computer{
		HostName:          "iME-host1",
		SAMAccountName:    "iME$host1$",
		DNSFQDN:           "iME-host1.vprodemo.com",
		UserPrincipalName: "iME-host1@vprodemo.com",
		DistinguishedName: "CN=iME-host1,CN=Computers,DC=vprodemo,DC=com",
		GUID:              "0d1e2f3a-4b5c-6d7e-8f90-a1b2c3d4e5f6",
		Password:          "Secret-P@ssw0rd-1234",
	}
}

func fullSettings() config.EA {
	return config.EA{
		Enabled:        true,
		URL:            "https://console.vprodemo.com:8181/ea",
		Username:       "eauser",
		Password:       "eapass",
		DeviceNameType: "hostname",
		AD: config.EAActiveDirectory{
			Domain:         "vprodemo.com",
			Server:         "dc1.vprodemo.com:636",
			BindUsername:   "svc-ea@vprodemo.com",
			BindPassword:   "bindpass",
			ComputerOU:     "CN=Computers",
			SecurityGroups: []string{"CN=AMT Devices,CN=Users,DC=vprodemo,DC=com"},
		},
		CA: config.EACertificateAuthority{
			Host:       "ca1.vprodemo.com",
			Name:       "vprodemo-CA",
			Template:   "AMT8021X",
			CommonName: "dnsfqdn",
			AltNames:   []string{"distinguishedname", "dnsfqdn", "hostname", "userprincipalname", "samaccountname", "uuid"},
		},
	}
}

// testCA is a self-signed CA able to issue leaf certificates.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             testNow.Add(-24 * time.Hour),
		NotAfter:              testNow.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return &testCA{cert: cert, key: key, der: der}
}

func (c *testCA) issue(t *testing.T, serial int64, notBefore, notAfter time.Time) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "iME-host1.vprodemo.com"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	require.NoError(t, err)

	return der
}
