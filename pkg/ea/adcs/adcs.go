// Package adcs talks to a Microsoft Active Directory Certificate Services CA
// over MS-RPC: MS-ICPR to submit requests and MS-CSRA to revoke.
//
// It replaces the .NET EA's COM interop with certcli.dll (ICertRequest) and
// certadm.dll (ICertAdmin).
package adcs

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wcce"
	"github.com/oiweiwei/go-msrpc/msrpc/epm/epm/v3"
	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32" // readable Win32 error messages
	"github.com/oiweiwei/go-msrpc/msrpc/icpr/icertpassage/v0"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
)

// ErrNotImplemented marks skeleton functions not written yet.
var ErrNotImplemented = errors.New("adcs: not implemented")

// ErrNotIssued is returned (wrapped) when the CA answers with any disposition
// other than issued; Result still carries the disposition and message.
var ErrNotIssued = errors.New("adcs: certificate not issued")

// Configuration errors (wrapped).
var (
	ErrNoHost        = errors.New("adcs: CA host is empty")
	ErrNoCAName      = errors.New("adcs: CA name is empty")
	ErrNoCredentials = errors.New("adcs: username or password is empty")
	ErrBadSerial     = errors.New("adcs: serial number must be hexadecimal")
	ErrEmptyRequest  = errors.New("adcs: certificate request is empty")
	ErrBadReason     = errors.New("adcs: invalid revocation reason")
)

var errNoInterface = errors.New("no interface or OXID bindings returned")

// Disposition values from MS-WCCE / MS-ICPR.
const (
	DispositionIncomplete      uint32 = 0
	DispositionError           uint32 = 1
	DispositionDenied          uint32 = 2
	DispositionIssued          uint32 = 3
	DispositionIssuedOutOfBand uint32 = 4
	DispositionUnderSubmission uint32 = 5
	DispositionRevoked         uint32 = 6
)

// Revocation reasons (RFC 5280 CRLReason), as ICertAdmin::RevokeCertificate takes them.
const (
	ReasonUnspecified          = 0
	ReasonKeyCompromise        = 1
	ReasonCACompromise         = 2
	ReasonAffiliationChanged   = 3
	ReasonSuperseded           = 4
	ReasonCessationOfOperation = 5
	ReasonCertificateHold      = 6
)

// crInPKCS10 is the dwFlags value for a binary PKCS#10 request: RequestType
// byte 0x01 (MS-WCCE 3.2.1.4.3.1.1), i.e. CR_IN_PKCS10. On the wire the
// request is always binary; CR_IN_BASE64/CR_IN_BINARY only exist in the
// certcli.dll client API.
const crInPKCS10 uint32 = 0x100

const defaultTimeout = 30 * time.Second

// Config says how to reach the CA.
type Config struct {
	// Host is the CA server's DNS name.
	Host string
	// CAName is the CA common name (the "Authority" in MS-ICPR).
	CAName string
	// Domain, Username and Password authenticate the RPC session (NTLM via
	// SPNEGO, sealed). Username may be a UPN or a bare sAMAccountName.
	Domain   string
	Username string
	Password string
	// Timeout bounds each call; zero means 30 seconds.
	Timeout time.Duration
}

// Result is the CA's answer to a submission.
type Result struct {
	Disposition uint32
	RequestID   uint32
	// Certificate is the issued certificate (DER) when Disposition is issued.
	Certificate []byte
	// Message is the CA's disposition message, if any.
	Message string
}

// Client is a CA client. Each call opens its own RPC connection.
type Client struct {
	cfg Config
	// icprEndpoint, when set ("host[port]"), skips the endpoint mapper (tests).
	icprEndpoint string
}

// New returns a client for cfg.
func New(cfg Config) *Client {
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}

	return &Client{cfg: cfg}
}

// Ping connects and binds the MS-ICPR interface without submitting anything.
func (c *Client) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	cc, _, err := c.dialICPR(ctx)
	if err != nil {
		return fmt.Errorf("adcs.Ping: %w", err)
	}

	_ = cc.Close(ctx)

	return nil
}

// Submit sends a DER PKCS#10 request (signed by AMT) with the attribute
// "CertificateTemplate:<template>" when template is set.
func (c *Client) Submit(ctx context.Context, csrDER []byte, template string) (Result, error) {
	if len(csrDER) == 0 {
		return Result{}, ErrEmptyRequest
	}

	if c.cfg.CAName == "" {
		return Result{}, ErrNoCAName
	}

	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	cc, cli, err := c.dialICPR(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("adcs.Submit: %w", err)
	}

	defer func() { _ = cc.Close(ctx) }()

	resp, callErr := cli.CertServerRequest(ctx, &icertpassage.CertServerRequestRequest{
		Flags:      crInPKCS10,
		Authority:  c.cfg.CAName,
		Attributes: blob(templateAttributes(template)),
		Request:    blob(csrDER),
	})
	if resp == nil {
		return Result{}, fmt.Errorf("adcs.Submit: %w", callErr)
	}

	res := Result{
		Disposition: resp.Disposition,
		RequestID:   resp.RequestID,
		Certificate: blobBytes(resp.EncodedCert),
		Message:     decodeUTF16(blobBytes(resp.DispositionMessage)),
	}

	if err := dispositionError(res, callErr); err != nil {
		return res, fmt.Errorf("adcs.Submit: %w", err)
	}

	return res, nil
}

// dispositionError maps a CA answer to an error: nil only when issued and
// the call succeeded; ErrNotIssued (wrapped) for any other disposition.
func dispositionError(res Result, callErr error) error {
	if res.Disposition == DispositionIssued && callErr == nil {
		return nil
	}

	if res.Disposition == DispositionIssued {
		return callErr
	}

	msg := strings.TrimSpace(res.Message)
	if msg == "" {
		msg = dispositionName(res.Disposition)
	}

	if callErr != nil {
		return fmt.Errorf("%w (request %d, %s): %s: %w", ErrNotIssued, res.RequestID, dispositionName(res.Disposition), msg, callErr)
	}

	return fmt.Errorf("%w (request %d, %s): %s", ErrNotIssued, res.RequestID, dispositionName(res.Disposition), msg)
}

func dispositionName(d uint32) string {
	switch d {
	case DispositionIncomplete:
		return "incomplete"
	case DispositionError:
		return "error"
	case DispositionDenied:
		return "denied"
	case DispositionIssued:
		return "issued"
	case DispositionIssuedOutOfBand:
		return "issued out of band"
	case DispositionUnderSubmission:
		return "pending"
	case DispositionRevoked:
		return "revoked"
	default:
		return fmt.Sprintf("disposition %d", d)
	}
}

// dialICPR connects to the CA's ICertPassage endpoint (through the endpoint
// mapper) and binds it with SPNEGO/NTLM and packet privacy.
func (c *Client) dialICPR(ctx context.Context) (dcerpc.Conn, icertpassage.CertPassageClient, error) {
	if c.cfg.Host == "" {
		return nil, nil, ErrNoHost
	}

	if c.cfg.Username == "" || c.cfg.Password == "" {
		return nil, nil, ErrNoCredentials
	}

	ctx = gssapi.NewSecurityContext(ctx)

	addr := "ncacn_ip_tcp:" + c.cfg.Host
	dialOpts := []dcerpc.Option{dcerpc.WithTimeout(c.cfg.Timeout)}

	if c.icprEndpoint != "" {
		addr = "ncacn_ip_tcp:" + c.icprEndpoint
	} else {
		dialOpts = append(dialOpts, epm.EndpointMapper(ctx, addr, dcerpc.WithInsecure(), dcerpc.WithTimeout(c.cfg.Timeout)))
	}

	cc, err := dcerpc.Dial(ctx, addr, dialOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("dial %s: %w", c.cfg.Host, err)
	}

	cli, err := icertpassage.NewCertPassageClient(ctx, cc, c.securityOptions()...)
	if err != nil {
		_ = cc.Close(ctx)

		return nil, nil, fmt.Errorf("bind ICertPassage on %s: %w", c.cfg.Host, err)
	}

	return cc, cli, nil
}

// securityOptions authenticates with SPNEGO (NTLM) and seals every packet;
// CAs enforce privacy (IF_ENFORCEENCRYPTICERTREQUEST).
func (c *Client) securityOptions() []dcerpc.Option {
	return []dcerpc.Option{
		dcerpc.WithSeal(),
		dcerpc.WithMechanism(ssp.SPNEGO),
		dcerpc.WithMechanism(ssp.NTLM),
		dcerpc.WithCredentials(c.credential()),
	}
}

func (c *Client) credential() credential.Password {
	if c.cfg.Domain != "" && !strings.ContainsAny(c.cfg.Username, `\@`) {
		return credential.NewFromPassword(c.cfg.Username, c.cfg.Password, credential.Domain(c.cfg.Domain))
	}

	return credential.NewFromPassword(c.cfg.Username, c.cfg.Password)
}

// templateAttributes returns the pctbAttribs bytes: UTF-16LE
// "CertificateTemplate:<template>" with its NUL terminator, or nil.
func templateAttributes(template string) []byte {
	if template == "" {
		return nil
	}

	return encodeUTF16("CertificateTemplate:" + template + "\x00")
}

func blob(b []byte) *wcce.CertTransportBlob {
	if len(b) == 0 {
		return &wcce.CertTransportBlob{}
	}

	return &wcce.CertTransportBlob{Length: uint32(len(b)), Buffer: b} //nolint:gosec // request sizes are far below 4 GiB
}

func blobBytes(b *wcce.CertTransportBlob) []byte {
	if b == nil || len(b.Buffer) == 0 {
		return nil
	}

	n := int(b.Length)
	if n > len(b.Buffer) || n == 0 {
		n = len(b.Buffer)
	}

	return b.Buffer[:n]
}

func encodeUTF16(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(units)*2) //nolint:mnd // two bytes per UTF-16 unit

	for _, u := range units {
		out = append(out, byte(u&0xff), byte(u>>8)) //nolint:mnd // little-endian bytes
	}

	return out
}

// decodeUTF16 decodes UTF-16LE up to the first NUL.
func decodeUTF16(b []byte) string {
	units := make([]uint16, 0, len(b)/2) //nolint:mnd // two bytes per UTF-16 unit

	for i := 0; i+1 < len(b); i += 2 {
		u := uint16(b[i]) | uint16(b[i+1])<<8 //nolint:mnd // little-endian high byte
		if u == 0 {
			break
		}

		units = append(units, u)
	}

	return string(utf16.Decode(units))
}
