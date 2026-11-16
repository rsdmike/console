// Package ad manages the Active Directory objects the Enterprise Assistant
// needs, over LDAPS with a simple bind as a service account.
//
// It replaces the .NET EA's System.DirectoryServices (ADSI) code.
package ad

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// ErrNotImplemented marks skeleton functions not written yet.
var ErrNotImplemented = errors.New("ad: not implemented")

// Errors returned (wrapped) by this package.
var (
	ErrNoBindPassword     = errors.New("ad: bind password is empty (an empty simple bind is anonymous)")
	ErrNoBindUsername     = errors.New("ad: bind username is empty")
	ErrNoServer           = errors.New("ad: no domain controller: set Server or Domain")
	ErrNoNamingContext    = errors.New("ad: rootDSE has no defaultNamingContext")
	ErrNoName             = errors.New("ad: computer name is empty")
	ErrBadGUID            = errors.New("ad: objectGUID is not 16 bytes")
	ErrPasswordGeneration = errors.New("ad: could not generate an AMT-compatible password")
)

const (
	defaultPort    = "636"
	defaultTimeout = 15 * time.Second
	pageSize       = 500
	defaultOU      = "CN=Computers"
	attrDN         = "distinguishedName"
)

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

// conn is the part of *ldap.Conn the client uses; tests substitute a fake.
type conn interface {
	Bind(username, password string) error
	Search(req *ldap.SearchRequest) (*ldap.SearchResult, error)
	SearchWithPaging(req *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error)
	Add(req *ldap.AddRequest) error
	Modify(req *ldap.ModifyRequest) error
	Del(req *ldap.DelRequest) error
	Close() error
	SetTimeout(timeout time.Duration)
}

// Client is a bound LDAPS session. It is not safe for concurrent use.
type Client struct {
	conn     conn
	server   string
	baseDN   string
	configDN string
	domain   string
}

// dialer holds the network dependencies of Dial.
type dialer struct {
	lookupSRV func(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
	open      func(host, port string, cfg Config, timeout time.Duration) (conn, error)
}

// Dial connects, binds, and reads the rootDSE (defaultNamingContext,
// configurationNamingContext).
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	return dialer{lookupSRV: net.DefaultResolver.LookupSRV, open: openLDAPS}.dial(ctx, cfg)
}

func openLDAPS(host, port string, cfg Config, timeout time.Duration) (conn, error) {
	tlsConfig := &tls.Config{
		ServerName:         host,
		RootCAs:            cfg.RootCAs,
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // operator opt-in for lab domain controllers
		MinVersion:         tls.VersionTLS12,
	}

	c, err := ldap.DialURL("ldaps://"+net.JoinHostPort(host, port),
		ldap.DialWithTLSConfig(tlsConfig),
		ldap.DialWithDialer(&net.Dialer{Timeout: timeout}))
	if err != nil {
		return nil, fmt.Errorf("ad.Dial: %w", err)
	}

	return c, nil
}

func (d dialer) dial(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.BindUsername == "" {
		return nil, ErrNoBindUsername
	}

	if cfg.BindPassword == "" {
		return nil, ErrNoBindPassword
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	host, port, err := d.resolve(ctx, cfg)
	if err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("ad.Dial: %w", err)
	}

	c, err := d.open(host, port, cfg, timeout)
	if err != nil {
		return nil, err
	}

	c.SetTimeout(timeout)

	client := &Client{conn: c, server: host}

	if err := client.bindAndReadRootDSE(cfg); err != nil {
		_ = c.Close()

		return nil, err
	}

	return client, nil
}

// resolve returns the domain controller host and port.
func (d dialer) resolve(ctx context.Context, cfg Config) (host, port string, err error) {
	if cfg.Server != "" {
		host, port, err = net.SplitHostPort(cfg.Server)
		if err != nil {
			return cfg.Server, defaultPort, nil //nolint:nilerr // no port given
		}

		return host, port, nil
	}

	if cfg.Domain == "" {
		return "", "", ErrNoServer
	}

	_, addrs, err := d.lookupSRV(ctx, "ldap", "tcp", "dc._msdcs."+cfg.Domain)
	if err != nil {
		return "", "", fmt.Errorf("ad.Dial: SRV lookup: %w", err)
	}

	if len(addrs) == 0 {
		return "", "", fmt.Errorf("%w: no SRV records for %s", ErrNoServer, cfg.Domain)
	}

	return strings.TrimSuffix(addrs[0].Target, "."), defaultPort, nil
}

func (c *Client) bindAndReadRootDSE(cfg Config) error {
	if err := c.conn.Bind(cfg.BindUsername, cfg.BindPassword); err != nil {
		return fmt.Errorf("ad.Dial: bind as %s: %w", cfg.BindUsername, err)
	}

	res, err := c.conn.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{"defaultNamingContext", "configurationNamingContext"}, nil))
	if err != nil {
		return fmt.Errorf("ad.Dial: read rootDSE: %w", err)
	}

	if len(res.Entries) == 0 {
		return ErrNoNamingContext
	}

	c.baseDN = res.Entries[0].GetAttributeValue("defaultNamingContext")
	c.configDN = res.Entries[0].GetAttributeValue("configurationNamingContext")

	if c.baseDN == "" {
		return ErrNoNamingContext
	}

	c.domain = domainFromDN(c.baseDN)

	return nil
}

// domainFromDN joins the DC components of dn with dots, lowercased.
func domainFromDN(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil {
		return ""
	}

	var parts []string

	for _, rdn := range parsed.RDNs {
		for _, atv := range rdn.Attributes {
			if strings.EqualFold(atv.Type, "DC") {
				parts = append(parts, strings.ToLower(atv.Value))
			}
		}
	}

	return strings.Join(parts, ".")
}

// Close unbinds and closes the connection.
func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}

	if err := c.conn.Close(); err != nil {
		return fmt.Errorf("ad.Close: %w", err)
	}

	return nil
}

// DomainName is the DNS domain derived from the base DN.
func (c *Client) DomainName() string { return c.domain }

// BaseDN is the defaultNamingContext, e.g. DC=vprodemo,DC=com.
func (c *Client) BaseDN() string { return c.baseDN }

// ServerName is the domain controller actually used.
func (c *Client) ServerName() string { return c.server }

// RemoveComputer deletes CN=iME-<name>,<ou>,<base DN>; false when absent.
func (c *Client) RemoveComputer(ctx context.Context, name, ou string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("ad.RemoveComputer: %w", err)
	}

	if name == "" {
		return false, ErrNoName
	}

	dn := c.computerDN(name, ou)

	exists, err := c.exists(dn)
	if err != nil {
		return false, fmt.Errorf("ad.RemoveComputer: %w", err)
	}

	if !exists {
		return false, nil
	}

	if err := c.treeDelete(dn); err != nil {
		return false, fmt.Errorf("ad.RemoveComputer: %w", err)
	}

	return true, nil
}

// Containers lists OUs and containers as DNs relative to the base DN.
func (c *Client) Containers(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("ad.Containers: %w", err)
	}

	res, err := c.conn.SearchWithPaging(ldap.NewSearchRequest(c.baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(|(objectCategory=organizationalUnit)(objectCategory=container))", []string{attrDN}, nil), pageSize)
	if err != nil {
		return nil, fmt.Errorf("ad.Containers: %w", err)
	}

	suffix := "," + strings.ToLower(c.baseDN)
	out := []string{}

	for _, e := range res.Entries {
		lower := strings.ToLower(e.DN)
		if !strings.HasSuffix(lower, suffix) {
			continue
		}

		out = append(out, e.DN[:len(e.DN)-len(suffix)])
	}

	sort.Strings(out)

	return out, nil
}

// SecurityGroups lists security-enabled group DNs in the domain.
func (c *Client) SecurityGroups(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("ad.SecurityGroups: %w", err)
	}

	res, err := c.conn.SearchWithPaging(ldap.NewSearchRequest(c.baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectCategory=group)(groupType:1.2.840.113556.1.4.803:=2147483648))", []string{attrDN}, nil), pageSize)
	if err != nil {
		return nil, fmt.Errorf("ad.SecurityGroups: %w", err)
	}

	out := make([]string, 0, len(res.Entries))
	for _, e := range res.Entries {
		out = append(out, e.DN)
	}

	sort.Strings(out)

	return out, nil
}

// CertificateAuthorities lists enterprise CAs with their templates and certificates.
func (c *Client) CertificateAuthorities(ctx context.Context) ([]CertificateAuthority, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("ad.CertificateAuthorities: %w", err)
	}

	if c.configDN == "" {
		return nil, fmt.Errorf("ad.CertificateAuthorities: %w", ErrNoNamingContext)
	}

	base := "CN=Enrollment Services,CN=Public Key Services,CN=Services," + c.configDN

	res, err := c.conn.SearchWithPaging(ldap.NewSearchRequest(base, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false,
		"(objectCategory=pKIEnrollmentService)", []string{"cn", "dNSHostName", "certificateTemplates", "cACertificate"}, nil), pageSize)
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return []CertificateAuthority{}, nil
	}

	if err != nil {
		return nil, fmt.Errorf("ad.CertificateAuthorities: %w", err)
	}

	out := make([]CertificateAuthority, 0, len(res.Entries))

	for _, e := range res.Entries {
		templates := e.GetAttributeValues("certificateTemplates")
		if templates == nil {
			templates = []string{}
		}

		out = append(out, CertificateAuthority{
			Name:        e.GetAttributeValue("cn"),
			Host:        e.GetAttributeValue("dNSHostName"),
			Templates:   templates,
			Certificate: e.GetRawAttributeValue("cACertificate"),
		})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

	return out, nil
}

// exists reports whether dn exists (a base search; noSuchObject means absent).
func (c *Client) exists(dn string) (bool, error) {
	_, err := c.conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{attrDN}, nil))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return false, nil
	}

	if err != nil {
		return false, err
	}

	return true, nil
}

// treeDelete deletes dn and everything below it (tree delete control, critical).
func (c *Client) treeDelete(dn string) error {
	ctrl := ldap.NewControlString(ldap.ControlTypeSubtreeDelete, true, "")

	return c.conn.Del(ldap.NewDelRequest(dn, []ldap.Control{ctrl}))
}
