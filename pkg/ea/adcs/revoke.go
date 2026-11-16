package adcs

import (
	"context"
	"fmt"
	"time"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/midl/uuid"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom"
	csra "github.com/oiweiwei/go-msrpc/msrpc/dcom/csra/client"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/csra/icertadmind/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/iactivation/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/iobjectexporter/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	"github.com/oiweiwei/go-msrpc/msrpc/erref/hresult"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
)

// clsidCertAdminD is CLSID_CCertAdminD (MS-CSRA 1.9).
var clsidCertAdminD = uuid.MustParse("d99e6e73-fc88-11d0-b498-00a0c90312f3")

// DCOM protocol sequence ids for RemoteActivation (MS-DCOM 2.2.19.3).
const (
	protseqTCP        uint16 = 7
	protseqNamedPipes uint16 = 15
)

// filetimeEpochOffset is the number of 100 ns intervals from 1601-01-01 to 1970-01-01.
const filetimeEpochOffset = 116444736000000000

// Revoke revokes the certificate with the given hex serial number.
//
// It activates CCertAdminD over DCOM (endpoint mapper port 135, then the
// OXID binding the CA returns) and calls ICertAdminD::RevokeCertificate,
// sealed with the configured credentials. The account needs "Issue and
// Manage Certificates" on the CA.
func (c *Client) Revoke(ctx context.Context, serialHex string, reason int, when time.Time) error {
	if err := c.checkRevoke(serialHex); err != nil {
		return err
	}

	if reason < 0 {
		return fmt.Errorf("%w: %d", ErrBadReason, reason)
	}

	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	ctx = gssapi.NewSecurityContext(ctx)

	version, act, err := c.activateCertAdmin(ctx)
	if err != nil {
		return fmt.Errorf("adcs.Revoke: %w", err)
	}

	conn, err := dcerpc.Dial(ctx, "ncacn_ip_tcp:"+c.cfg.Host,
		append(act.OXIDBindings.EndpointsByProtocol("ncacn_ip_tcp"), dcerpc.WithTimeout(c.cfg.Timeout))...)
	if err != nil {
		return fmt.Errorf("adcs.Revoke: dial CertAdminD: %w", err)
	}

	defer func() { _ = conn.Close(ctx) }()

	ctx = gssapi.NewSecurityContext(ctx)

	cli, err := csra.NewClient(ctx, conn, c.securityOptions()...)
	if err != nil {
		return fmt.Errorf("adcs.Revoke: bind CertAdminD: %w", err)
	}

	cli = cli.IPID(ctx, act.InterfaceData[0].IPID())

	_, err = cli.CertAdminD().RevokeCertificate(ctx, &icertadmind.RevokeCertificateRequest{
		This:         &dcom.ORPCThis{Version: version},
		Authority:    c.cfg.CAName,
		SerialNumber: serialHex,
		Reason:       uint32(reason), //nolint:gosec // checked non-negative above
		FileTime:     filetime(when),
	})
	if err != nil {
		return fmt.Errorf("adcs.Revoke: RevokeCertificate %s: %w", serialHex, err)
	}

	return nil
}

func (c *Client) checkRevoke(serialHex string) error {
	if c.cfg.Host == "" {
		return ErrNoHost
	}

	if c.cfg.CAName == "" {
		return ErrNoCAName
	}

	if c.cfg.Username == "" || c.cfg.Password == "" {
		return ErrNoCredentials
	}

	if !isHex(serialHex) {
		return fmt.Errorf("%w: %q", ErrBadSerial, serialHex)
	}

	return nil
}

// activateCertAdmin asks the CA's object exporter (port 135) to activate
// CCertAdminD and returns the COM version and the activation answer.
func (c *Client) activateCertAdmin(ctx context.Context) (*dcom.COMVersion, *iactivation.RemoteActivationResponse, error) {
	cc, err := dcerpc.Dial(ctx, "ncacn_ip_tcp:"+c.cfg.Host+"[135]", dcerpc.WithTimeout(c.cfg.Timeout))
	if err != nil {
		return nil, nil, fmt.Errorf("dial object exporter: %w", err)
	}

	defer func() { _ = cc.Close(ctx) }()

	exporter, err := iobjectexporter.NewObjectExporterClient(ctx, cc, c.securityOptions()...)
	if err != nil {
		return nil, nil, fmt.Errorf("bind object exporter: %w", err)
	}

	alive, err := exporter.ServerAlive2(ctx, &iobjectexporter.ServerAlive2Request{})
	if err != nil {
		return nil, nil, fmt.Errorf("ServerAlive2: %w", err)
	}

	activation, err := iactivation.NewActivationClient(ctx, cc, c.securityOptions()...)
	if err != nil {
		return nil, nil, fmt.Errorf("bind activation: %w", err)
	}

	act, err := activation.RemoteActivation(ctx, &iactivation.RemoteActivationRequest{
		ORPCThis:                   &dcom.ORPCThis{Version: alive.COMVersion},
		ClassID:                    dtyp.GUIDFromUUID(clsidCertAdminD),
		IIDs:                       []*dcom.IID{icertadmind.CertAdminDIID},
		RequestedProtocolSequences: []uint16{protseqTCP, protseqNamedPipes},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("RemoteActivation: %w", err)
	}

	if act.HResult != 0 {
		return nil, nil, fmt.Errorf("RemoteActivation: %w", hresult.FromCode(uint32(act.HResult))) //nolint:gosec // HRESULT bit pattern
	}

	if len(act.InterfaceData) == 0 || act.InterfaceData[0] == nil || act.OXIDBindings == nil {
		return nil, nil, fmt.Errorf("RemoteActivation: %w", errNoInterface)
	}

	return alive.COMVersion, act, nil
}

// filetime converts t to a Windows FILETIME (100 ns since 1601-01-01 UTC).
// The zero time maps to a zero FILETIME, which the CA treats as "now".
func filetime(t time.Time) *dtyp.Filetime {
	if t.IsZero() {
		return &dtyp.Filetime{}
	}

	const (
		ticksPerSecond  = 10_000_000
		nanosPerTick    = 100
		secondsTo1970   = filetimeEpochOffset / ticksPerSecond
		maxFiletimeSecs = (1<<63 - 1) / ticksPerSecond
	)

	sec := t.Unix() + secondsTo1970
	if sec < 0 {
		return &dtyp.Filetime{}
	}

	if sec > maxFiletimeSecs-1 {
		sec = maxFiletimeSecs - 1
	}

	u := uint64(sec)*ticksPerSecond + uint64(t.Nanosecond()/nanosPerTick) //nolint:gosec // sec is non-negative and bounded

	return &dtyp.Filetime{LowDateTime: uint32(u & 0xffffffff), HighDateTime: uint32(u >> 32)} //nolint:mnd // split 64-bit value
}

func isHex(s string) bool {
	if s == "" {
		return false
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}

	return true
}
