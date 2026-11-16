package enterpriseassistant

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/device-management-toolkit/console/config"
	dto "github.com/device-management-toolkit/console/internal/entity/dto/v2"
	"github.com/device-management-toolkit/console/pkg/ea/ad"
	"github.com/device-management-toolkit/console/pkg/ea/adcs"
	"github.com/device-management-toolkit/console/pkg/ea/csr"
)

const testGUID = "4c4c4544-0046-3310-8051-b2c04f305032"

var errBoom = errors.New("boom")

func profileReq(proto int) dto.EADeviceRequest {
	return dto.EADeviceRequest{NodeID: testGUID, AuthProtocol: proto, OSName: "win11", DevName: "host1", Icon: 1}
}

func TestDeviceValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		call func(uc *UseCase) error
		want string
	}{
		{"profile missing nodeid", func(uc *UseCase) error {
			_, err := uc.Profile(context.Background(), dto.EADeviceRequest{})

			return err
		}, "Validation failed: Nodeid is required."},
		{"profile bad protocol and nodeid", func(uc *UseCase) error {
			_, err := uc.Profile(context.Background(), dto.EADeviceRequest{AuthProtocol: 1})

			return err
		}, "Validation failed: Nodeid is required., AuthProtocol must be 0 or 2."},
		{"keypair missing everything", func(uc *UseCase) error {
			_, err := uc.KeyPair(context.Background(), dto.EADeviceRequest{AuthProtocol: 2})

			return err
		}, "Validation failed: Nodeid is required., AuthProtocol must be 0, DERKey is required., KeyInstanceId is required."},
		{"keypair DERKey not base64", func(uc *UseCase) error {
			_, err := uc.KeyPair(context.Background(), dto.EADeviceRequest{NodeID: testGUID, DERKey: "!!", KeyInstanceID: "k"})

			return err
		}, "Validation failed: DERKey is not valid base64."},
		{"csr missing everything", func(uc *UseCase) error {
			_, err := uc.CSR(context.Background(), dto.EADeviceRequest{AuthProtocol: 2})

			return err
		}, "Validation failed: Nodeid is required., AuthProtocol must be 0, Signedcsr is required."},
		{"csr signedcsr not base64", func(uc *UseCase) error {
			_, err := uc.CSR(context.Background(), dto.EADeviceRequest{NodeID: testGUID, SignedCSR: "%%"})

			return err
		}, "Validation failed: Signedcsr is not valid base64."},
		{"remove missing nodeid", func(uc *UseCase) error {
			_, err := uc.Remove(context.Background(), dto.EADeviceRequest{})

			return err
		}, "Validation failed: Nodeid is required."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, fullSettings())
			err := tt.call(h.uc)

			require.ErrorIs(t, err, ErrValidation)
			require.EqualError(t, err, tt.want)
			require.Empty(t, h.dialCfgs, "validation must fail before AD is dialed")
		})
	}
}

func TestDeviceNotConfigured(t *testing.T) {
	t.Parallel()

	noCA := fullSettings()
	noCA.CA.Host = ""

	noAD := fullSettings()
	noAD.AD.BindPassword = ""

	tests := []struct {
		name     string
		settings config.EA
		call     func(uc *UseCase) error
		want     string
	}{
		{"eap-tls profile without CA", noCA, func(uc *UseCase) error {
			_, err := uc.Profile(context.Background(), profileReq(0))

			return err
		}, errCANotConfigured.msg},
		{"keypair without CA", noCA, func(uc *UseCase) error {
			_, err := uc.KeyPair(context.Background(), dto.EADeviceRequest{NodeID: testGUID, DERKey: "AQID", KeyInstanceID: "k"})

			return err
		}, errCANotConfigured.msg},
		{"csr without CA", noCA, func(uc *UseCase) error {
			_, err := uc.CSR(context.Background(), dto.EADeviceRequest{NodeID: testGUID, SignedCSR: "AQID"})

			return err
		}, errCANotConfigured.msg},
		{"peap without AD", noAD, func(uc *UseCase) error {
			_, err := uc.Profile(context.Background(), profileReq(2))

			return err
		}, errADNotConfigured.msg},
		{"remove without AD", noAD, func(uc *UseCase) error {
			_, err := uc.Remove(context.Background(), dto.EADeviceRequest{NodeID: testGUID})

			return err
		}, errADNotConfigured.msg},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, tt.settings)
			err := tt.call(h.uc)

			require.ErrorIs(t, err, ErrNotConfigured)
			require.NotErrorIs(t, err, ErrUpstream)
			require.EqualError(t, err, tt.want)
		})
	}
}

func TestProfilePEAP(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t, "vprodemo-CA")
	s := fullSettings()
	s.CA.Host = "" // PEAP does not need the CA host
	h := newHarness(t, s)
	h.dir.cas = []ad.CertificateAuthority{{Name: "VPRODEMO-ca", Certificate: ca.der}}

	req := profileReq(2)
	req.Ver = "16.1"

	resp, err := h.uc.Profile(context.Background(), req)
	require.NoError(t, err)

	require.Equal(t, "satellite", resp.Action)
	require.Equal(t, 2, resp.SatelliteFlags)
	require.Equal(t, "Profile-Completed", resp.SubAction)
	require.Equal(t, req, resp.EADeviceRequest)
	require.Equal(t, 2, *resp.Response.AuthProtocol)
	require.Equal(t, "vprodemo.com", resp.Response.Domain)
	require.Equal(t, "iME$host1$", resp.Response.Username)
	require.Equal(t, "Secret-P@ssw0rd-1234", resp.Response.Password)
	require.Equal(t, base64.StdEncoding.EncodeToString(ca.der), resp.Response.RootCert)
	require.Empty(t, resp.Response.CertID)

	require.Equal(t, []ad.ComputerRequest{{
		Name:           "host1",
		Description:    "Intel(R) AMT v16.1 - " + testGUID,
		OU:             "CN=Computers",
		SecurityGroups: []string{"CN=AMT Devices,CN=Users,DC=vprodemo,DC=com"},
	}}, h.dir.ensureReqs)
	require.Equal(t, 1, h.dir.closed)
	require.Equal(t, ad.Config{
		Domain: "vprodemo.com", Server: "dc1.vprodemo.com:636", BindUsername: "svc-ea@vprodemo.com",
		BindPassword: "bindpass", Timeout: 15 * time.Second,
	}, h.dialCfgs[0])
}

func TestProfileUpstreamFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		setup func(h *harness)
	}{
		{"dial fails", func(h *harness) { h.dialErr = errBoom }},
		{"ensure computer fails", func(h *harness) { h.dir.ensureErr = errBoom }},
		{"listing CAs fails", func(h *harness) { h.dir.casErr = errBoom }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, fullSettings())
			tt.setup(h)

			_, err := h.uc.Profile(context.Background(), profileReq(2))
			require.ErrorIs(t, err, ErrUpstream)
			require.ErrorIs(t, err, errBoom)
		})
	}
}

func TestProfileEAPTLSReusesFreshCertificate(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t, "vprodemo-CA")
	h := newHarness(t, fullSettings())
	h.dir.cas = []ad.CertificateAuthority{{Name: "other-CA"}, {Name: "vprodemo-CA", Certificate: ca.der}}

	req := profileReq(0)
	req.Cert = base64.StdEncoding.EncodeToString(ca.issue(t, 0x1234, testNow.Add(-time.Hour), testNow.Add(10*time.Hour)))
	req.CertID = "Intel(r) AMT Certificate: Handle: 3"

	resp, err := h.uc.Profile(context.Background(), req)
	require.NoError(t, err)

	require.Equal(t, "Profile-Completed", resp.SubAction)
	require.Equal(t, 0, *resp.Response.AuthProtocol)
	require.Equal(t, req.CertID, resp.Response.CertID)
	require.Equal(t, "Secret-P@ssw0rd-1234", resp.Response.Password)
	require.Equal(t, "iME$host1$", resp.Response.Username)
	require.NotEmpty(t, resp.Response.RootCert)
	require.Empty(t, h.ca.revokes)
}

func TestProfileEAPTLSRequestsKeyPair(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t, "vprodemo-CA")
	otherCA := newTestCA(t, "other-CA")

	enc := base64.StdEncoding.EncodeToString

	tests := []struct {
		name      string
		cert      func() string
		certID    string
		revokeErr error
		revoked   []string
	}{
		{"no certificate", func() string { return "" }, "", nil, nil},
		{"certificate without certid", func() string {
			return enc(ca.issue(t, 0x10, testNow.Add(-time.Hour), testNow.Add(10*time.Hour)))
		}, "", nil, nil},
		{"garbage certificate", func() string { return enc([]byte("nope")) }, "h", nil, nil},
		{"past the validity midpoint", func() string {
			return enc(ca.issue(t, 0xABCD, testNow.Add(-10*time.Hour), testNow.Add(time.Hour)))
		}, "h", nil, []string{"ABCD"}},
		{"not yet valid", func() string {
			return enc(ca.issue(t, 0x0F01, testNow.Add(time.Hour), testNow.Add(10*time.Hour)))
		}, "h", nil, []string{"0F01"}},
		{"issued by another CA", func() string {
			return enc(otherCA.issue(t, 0x77, testNow.Add(-time.Hour), testNow.Add(10*time.Hour)))
		}, "h", nil, []string{"77"}},
		{"revoke failure is not fatal", func() string {
			return enc(ca.issue(t, 0x88, testNow.Add(-10*time.Hour), testNow.Add(time.Hour)))
		}, "h", errBoom, []string{"88"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, fullSettings())
			h.dir.cas = []ad.CertificateAuthority{{Name: "vprodemo-CA", Certificate: ca.der}}
			h.ca.revokeErr = tt.revokeErr

			req := profileReq(0)
			req.Cert = tt.cert()
			req.CertID = tt.certID

			resp, err := h.uc.Profile(context.Background(), req)
			require.NoError(t, err)

			require.Equal(t, "KeyPair-Request", resp.SubAction)
			require.Equal(t, "satellite", resp.Action)
			require.Equal(t, 2, resp.SatelliteFlags)

			body, err := json.Marshal(resp.Response)
			require.NoError(t, err)
			require.JSONEq(t, `{}`, string(body))

			require.Equal(t, tt.revoked, h.ca.revokes)
			require.Empty(t, h.dir.ensureReqs, "no computer is created before the key pair exists")

			if tt.revoked != nil {
				require.Equal(t, []int{adcs.ReasonCessationOfOperation}, h.ca.reasons)
				require.Equal(t, adcs.Config{
					Host: "ca1.vprodemo.com", CAName: "vprodemo-CA", Domain: "vprodemo.com",
					Username: "svc-ea@vprodemo.com", Password: "bindpass",
				}, h.caCfgs[0])
			}
		})
	}
}

func TestKeyPair(t *testing.T) {
	t.Parallel()

	derKey := []byte{0x30, 0x82, 0x01, 0x0a, 0x02}
	spns := []string{
		"HTTP/iME-host1.vprodemo.com:16992", "HTTP/iME-host1.vprodemo.com:16993", "HTTP/iME-host1.vprodemo.com:623",
		"HTTP/iME-host1.vprodemo.com:664", "HTTP/iME-host1.vprodemo.com:16994", "HTTP/iME-host1.vprodemo.com:16995",
		"HTTP/iME-host1.vprodemo.com:5900",
	}

	tests := []struct {
		name       string
		commonName string
		altNames   []string
		want       csr.Request
	}{
		{
			name:       "dnsfqdn subject, every other kind as SAN",
			commonName: "dnsfqdn",
			altNames:   []string{"distinguishedname", "dnsfqdn", "hostname", "userprincipalname", "samaccountname", "uuid"},
			want: csr.Request{
				SubjectDN: "CN=iME-host1.vprodemo.com",
				Names: csr.Names{
					DNS: []string{"iME-host1", "iME$host1$", "0d1e2f3a-4b5c-6d7e-8f90-a1b2c3d4e5f6"},
					UPN: append([]string{"iME-host1@vprodemo.com"}, spns...),
					URI: []string{"LDAP://CN=iME-host1,CN=Computers,DC=vprodemo,DC=com"},
				},
			},
		},
		{
			name:       "distinguishedname subject",
			commonName: "distinguishedname",
			altNames:   []string{"distinguishedname", "dnsfqdn"},
			want: csr.Request{
				SubjectDN: "CN=iME-host1,CN=Computers,DC=vprodemo,DC=com",
				Names:     csr.Names{DNS: []string{"iME-host1.vprodemo.com"}, UPN: spns},
			},
		},
		{
			name:       "upn subject, no alt names",
			commonName: "userprincipalname",
			want:       csr.Request{SubjectDN: "CN=iME-host1@vprodemo.com", Names: csr.Names{UPN: spns}},
		},
		{"hostname subject", "hostname", []string{"hostname"}, csr.Request{SubjectDN: "CN=iME-host1", Names: csr.Names{UPN: spns}}},
		{"samaccountname subject", "samaccountname", nil, csr.Request{SubjectDN: "CN=iME$host1$", Names: csr.Names{UPN: spns}}},
		{"uuid subject", "uuid", nil, csr.Request{SubjectDN: "CN=0d1e2f3a-4b5c-6d7e-8f90-a1b2c3d4e5f6", Names: csr.Names{UPN: spns}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := fullSettings()
			s.CA.CommonName = tt.commonName
			s.CA.AltNames = tt.altNames
			h := newHarness(t, s)

			req := dto.EADeviceRequest{
				NodeID: testGUID, DevName: "host1", DERKey: base64.StdEncoding.EncodeToString(derKey), KeyInstanceID: "Intel(r) AMT Key: Handle: 0",
			}

			resp, err := h.uc.KeyPair(context.Background(), req)
			require.NoError(t, err)

			want := tt.want
			want.PublicKey = derKey
			want.Template = "AMT8021X"
			require.Equal(t, []csr.Request{want}, h.csrReqs)

			require.Equal(t, "CSR-Request", resp.SubAction)
			require.Equal(t, base64.StdEncoding.EncodeToString(h.csrOut), resp.Response.CSR)
			require.NotContains(t, resp.Response.CSR, "\n")
			require.Equal(t, req.KeyInstanceID, resp.Response.KeyInstanceID)
			require.Nil(t, resp.Response.AuthProtocol)
			require.Len(t, h.dir.ensureReqs, 1)
			require.Equal(t, 1, h.dir.closed)
		})
	}
}

func TestKeyPairFailures(t *testing.T) {
	t.Parallel()

	t.Run("csr builder failure is internal", func(t *testing.T) {
		t.Parallel()

		h := newHarness(t, fullSettings())
		h.csrErr = errBoom

		_, err := h.uc.KeyPair(context.Background(), dto.EADeviceRequest{NodeID: testGUID, DERKey: "AQID", KeyInstanceID: "k"})
		require.ErrorIs(t, err, errBoom)
		require.NotErrorIs(t, err, ErrUpstream)
		require.NotErrorIs(t, err, ErrValidation)
	})

	t.Run("ensure computer failure is upstream", func(t *testing.T) {
		t.Parallel()

		h := newHarness(t, fullSettings())
		h.dir.ensureErr = errBoom

		_, err := h.uc.KeyPair(context.Background(), dto.EADeviceRequest{NodeID: testGUID, DERKey: "AQID", KeyInstanceID: "k"})
		require.ErrorIs(t, err, ErrUpstream)
		require.Empty(t, h.csrReqs)
	})
}

func TestCSR(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t, "vprodemo-CA")
	issued := ca.issue(t, 5, testNow.Add(-time.Hour), testNow.Add(time.Hour))
	signed := []byte{0x30, 0x01, 0x02}

	h := newHarness(t, fullSettings())
	h.dir.cas = []ad.CertificateAuthority{{Name: "vprodemo-ca", Certificate: ca.der}}
	h.ca.result = adcs.Result{Disposition: adcs.DispositionIssued, RequestID: 42, Certificate: issued}

	req := dto.EADeviceRequest{NodeID: testGUID, DevName: "host1", SignedCSR: base64.StdEncoding.EncodeToString(signed)}

	resp, err := h.uc.CSR(context.Background(), req)
	require.NoError(t, err)

	require.Equal(t, [][]byte{signed}, h.ca.submits)
	require.Equal(t, []string{"AMT8021X"}, h.ca.templates)
	require.Equal(t, "Profile-Completed", resp.SubAction)
	require.Equal(t, 0, *resp.Response.AuthProtocol)
	require.Equal(t, base64.StdEncoding.EncodeToString(issued), resp.Response.Certificate)
	require.Equal(t, base64.StdEncoding.EncodeToString(ca.der), resp.Response.RootCert)
	require.Equal(t, "vprodemo.com", resp.Response.Domain)
	require.Equal(t, "iME$host1$", resp.Response.Username)
	require.Empty(t, resp.Response.Password, "the csr answer never carries the computer password")
	require.Len(t, h.dir.ensureReqs, 1)
}

func TestCSRFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		setup     func(h *harness)
		notIssued bool
		ensured   int
	}{
		{"submit fails", func(h *harness) { h.ca.submitErr = errBoom }, false, 0},
		{"denied", func(h *harness) {
			h.ca.result = adcs.Result{Disposition: adcs.DispositionDenied, Message: "Denied by Policy Module"}
		}, true, 0},
		{"issued without a certificate", func(h *harness) {
			h.ca.result = adcs.Result{Disposition: adcs.DispositionIssued}
		}, true, 0},
		{"ensure computer fails", func(h *harness) {
			h.ca.result = adcs.Result{Disposition: adcs.DispositionIssued, Certificate: []byte{1}}
			h.dir.ensureErr = errBoom
		}, false, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, fullSettings())
			tt.setup(h)

			_, err := h.uc.CSR(context.Background(), dto.EADeviceRequest{NodeID: testGUID, SignedCSR: "AQID"})
			require.ErrorIs(t, err, ErrUpstream)

			if tt.notIssued {
				require.ErrorIs(t, err, adcs.ErrNotIssued)
			}

			require.Len(t, h.dir.ensureReqs, tt.ensured)
		})
	}
}

func TestRemove(t *testing.T) {
	t.Parallel()

	t.Run("hostname naming", func(t *testing.T) {
		t.Parallel()

		h := newHarness(t, fullSettings())
		h.dir.removed = true

		res, err := h.uc.Remove(context.Background(), dto.EADeviceRequest{NodeID: testGUID, DevName: "host1"})
		require.NoError(t, err)
		require.Equal(t, dto.EARemoveResult{Status: "Success", Removed: true}, res)
		require.Equal(t, [][2]string{{"host1", "CN=Computers"}}, h.dir.removeArgs)
	})

	t.Run("nodeid naming, absent computer", func(t *testing.T) {
		t.Parallel()

		s := fullSettings()
		s.DeviceNameType = "nodeid"
		h := newHarness(t, s)

		res, err := h.uc.Remove(context.Background(), dto.EADeviceRequest{NodeID: testGUID, DevName: "host1"})
		require.NoError(t, err)
		require.False(t, res.Removed)
		require.Equal(t, [][2]string{{"4c4c45440046", "CN=Computers"}}, h.dir.removeArgs)
	})

	t.Run("remove fails", func(t *testing.T) {
		t.Parallel()

		h := newHarness(t, fullSettings())
		h.dir.removeErr = errBoom

		_, err := h.uc.Remove(context.Background(), dto.EADeviceRequest{NodeID: testGUID})
		require.ErrorIs(t, err, ErrUpstream)
	})
}

func TestComputerNaming(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		nameType string
		req      dto.EADeviceRequest
		wantName string
		wantDesc string
	}{
		{"hostname uses devname", "hostname", dto.EADeviceRequest{NodeID: testGUID, DevName: "host1"}, "host1", "Intel(R) AMT device - " + testGUID},
		{"hostname falls back to nodeid", "hostname", dto.EADeviceRequest{NodeID: testGUID}, "4c4c45440046", "Intel(R) AMT device - " + testGUID},
		{"nodeid ignores devname", "NodeID", dto.EADeviceRequest{NodeID: testGUID, DevName: "host1", Ver: "16.1"}, "4c4c45440046", "Intel(R) AMT v16.1 - " + testGUID},
		{"short nodeid kept whole", "nodeid", dto.EADeviceRequest{NodeID: "ab-cd"}, "abcd", "Intel(R) AMT device - ab-cd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := config.EA{DeviceNameType: tt.nameType}
			got := computerRequest(&s, &tt.req)
			require.Equal(t, tt.wantName, got.Name)
			require.Equal(t, tt.wantDesc, got.Description)
			require.False(t, strings.ContainsRune(got.Description, '®'))
		})
	}
}

func TestRootCertCachedPerRevision(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t, "vprodemo-CA")
	h := newHarness(t, fullSettings())
	h.dir.cas = []ad.CertificateAuthority{{Name: "vprodemo-CA", Certificate: ca.der}}

	for range 2 {
		_, err := h.uc.Profile(context.Background(), profileReq(2))
		require.NoError(t, err)
	}

	require.Equal(t, 1, h.dir.casCalls, "second call is served from the cache")

	in := toDTO(&h.uc.settings)
	_, err := h.uc.UpdateSettings(context.Background(), in)
	require.NoError(t, err)

	_, err = h.uc.Profile(context.Background(), profileReq(2))
	require.NoError(t, err)
	require.Equal(t, 2, h.dir.casCalls, "a settings update invalidates the cache")

	t.Run("missing CA is not cached and omits rootcert", func(t *testing.T) {
		t.Parallel()

		h := newHarness(t, fullSettings())
		h.dir.cas = []ad.CertificateAuthority{{Name: "other-CA", Certificate: ca.der}}

		for range 2 {
			resp, err := h.uc.Profile(context.Background(), profileReq(2))
			require.NoError(t, err)
			require.Empty(t, resp.Response.RootCert)
		}

		require.Equal(t, 2, h.dir.casCalls)
	})

	t.Run("no CA name skips the lookup", func(t *testing.T) {
		t.Parallel()

		s := fullSettings()
		s.CA.Name = ""
		h := newHarness(t, s)

		_, err := h.uc.Profile(context.Background(), profileReq(2))
		require.NoError(t, err)
		require.Zero(t, h.dir.casCalls)
	})
}
