// Package adcs talks to a Microsoft Active Directory Certificate Services CA
// over MS-RPC: MS-ICPR to submit requests and MS-CSRA to revoke.
//
// It replaces the .NET EA's COM interop with certcli.dll (ICertRequest) and
// certadm.dll (ICertAdmin).
package adcs

import (
	"context"
	"errors"
	"time"
)

// ErrNotImplemented marks skeleton functions not written yet.
var ErrNotImplemented = errors.New("adcs: not implemented")

// ErrNotIssued is returned (wrapped) when the CA answers with any disposition
// other than issued; Result still carries the disposition and message.
var ErrNotIssued = errors.New("adcs: certificate not issued")

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
type Client struct{}

// New returns a client for cfg.
func New(_ Config) *Client { return &Client{} }

// Ping connects and binds the MS-ICPR interface without submitting anything.
func (c *Client) Ping(_ context.Context) error { return ErrNotImplemented }

// Submit sends a DER PKCS#10 request (signed by AMT) with the attribute
// "CertificateTemplate:<template>" when template is set.
func (c *Client) Submit(_ context.Context, _ []byte, _ string) (Result, error) {
	return Result{}, ErrNotImplemented
}

// Revoke revokes the certificate with the given hex serial number.
func (c *Client) Revoke(_ context.Context, _ string, _ int, _ time.Time) error {
	return ErrNotImplemented
}
