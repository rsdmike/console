// Package ad manages the Active Directory objects the Enterprise Assistant
// needs, over LDAPS with a simple bind as a service account.
//
// It replaces the .NET EA's System.DirectoryServices (ADSI) code.
package ad

import (
	"context"
	"crypto/x509"
	"errors"
	"time"
)

// ErrNotImplemented marks skeleton functions not written yet.
var ErrNotImplemented = errors.New("ad: not implemented")

// Config says how to reach and bind to a domain controller.
type Config struct {
	// Domain is the DNS domain, e.g. vprodemo.com.
	Domain string
	// Server is host[:port] of a domain controller. Empty means DNS SRV
	// discovery (_ldap._tcp.dc._msdcs.<Domain>). The port defaults to 636.
	Server string
	// BindUsername is the service account UPN, e.g. svc-ea@vprodemo.com.
	BindUsername string
	BindPassword string
	// RootCAs verifies the DC's LDAPS certificate; nil means the system pool.
	RootCAs            *x509.CertPool
	InsecureSkipVerify bool
	// Timeout bounds dialing and each operation; zero means 15 seconds.
	Timeout time.Duration
}

// ComputerRequest describes the AMT computer object to create or reset.
type ComputerRequest struct {
	// Name is the identifier; the object is CN=iME-<Name>.
	Name        string
	Description string
	// OU is the container relative to the domain root, e.g. "CN=Computers"
	// or "OU=AMT,OU=Devices". Empty means "CN=Computers".
	OU string
	// SecurityGroups are group DNs the computer joins. Missing groups are skipped.
	SecurityGroups []string
}

// Computer is the AD computer object as the EA flow uses it.
type Computer struct {
	HostName          string // iME-<Name>
	SAMAccountName    string // iME$<Name>$ (the .NET EA's format, kept for compatibility)
	DNSFQDN           string // iME-<Name>.<domain>
	UserPrincipalName string // iME-<Name>@<domain>
	DistinguishedName string // CN=iME-<Name>,<OU>,<base DN>
	// GUID is objectGUID in .NET Guid.ToString() form (first three groups little-endian).
	GUID string
	// Password is the new random 20-character AMT-compatible password just set.
	Password       string
	AlreadyPresent bool
}

// CertificateAuthority is an enterprise CA published in AD
// (pKIEnrollmentService under CN=Enrollment Services).
type CertificateAuthority struct {
	Name      string
	Host      string
	Templates []string
	// Certificate is the CA certificate (DER) from cACertificate.
	Certificate []byte
}

// Client is a bound LDAPS session. It is not safe for concurrent use.
type Client struct{}

// Dial connects, binds, and reads the rootDSE (defaultNamingContext,
// configurationNamingContext).
func Dial(_ context.Context, _ Config) (*Client, error) {
	return nil, ErrNotImplemented
}

// Close unbinds and closes the connection.
func (c *Client) Close() error { return nil }

// DomainName is the DNS domain derived from the base DN.
func (c *Client) DomainName() string { return "" }

// BaseDN is the defaultNamingContext, e.g. DC=vprodemo,DC=com.
func (c *Client) BaseDN() string { return "" }

// ServerName is the domain controller actually used.
func (c *Client) ServerName() string { return "" }

// EnsureComputer creates the computer object or finds the existing one,
// deletes same-named objects elsewhere in the domain, sets a new random
// password, reads objectGUID and joins the security groups.
func (c *Client) EnsureComputer(_ context.Context, _ ComputerRequest) (Computer, error) {
	return Computer{}, ErrNotImplemented
}

// RemoveComputer deletes CN=iME-<name>,<ou>,<base DN>; false when absent.
func (c *Client) RemoveComputer(_ context.Context, _, _ string) (bool, error) {
	return false, ErrNotImplemented
}

// Containers lists OUs and containers as DNs relative to the base DN.
func (c *Client) Containers(_ context.Context) ([]string, error) {
	return nil, ErrNotImplemented
}

// SecurityGroups lists security-enabled group DNs in the domain.
func (c *Client) SecurityGroups(_ context.Context) ([]string, error) {
	return nil, ErrNotImplemented
}

// CertificateAuthorities lists enterprise CAs with their templates and certificates.
func (c *Client) CertificateAuthorities(_ context.Context) ([]CertificateAuthority, error) {
	return nil, ErrNotImplemented
}
