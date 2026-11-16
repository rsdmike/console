package ad

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/go-ldap/ldap/v3"
)

const (
	testBase   = "DC=vprodemo,DC=com"
	testConfig = "CN=Configuration,DC=vprodemo,DC=com"
)

var testGUID = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

// fakeConn is an in-memory LDAP server: base searches look entries up by DN,
// other searches go to the subtree hook.
type fakeConn struct {
	mu        sync.Mutex
	entries   map[string]*ldap.Entry
	subtree   func(req *ldap.SearchRequest) []*ldap.Entry
	modifyErr map[string]error
	bindErr   error

	bindUser, bindPass string
	searches           []*ldap.SearchRequest
	adds               []*ldap.AddRequest
	modifies           []*ldap.ModifyRequest
	dels               []*ldap.DelRequest
	closed             bool
	timeout            time.Duration
}

func newFake(dns ...string) *fakeConn {
	f := &fakeConn{entries: map[string]*ldap.Entry{}, modifyErr: map[string]error{}}
	f.entries[""] = ldap.NewEntry("", map[string][]string{
		"defaultNamingContext":       {testBase},
		"configurationNamingContext": {testConfig},
	})

	for _, dn := range dns {
		f.put(dn)
	}

	return f
}

func (f *fakeConn) put(dn string) {
	f.entries[strings.ToLower(dn)] = ldap.NewEntry(dn, map[string][]string{"objectGUID": {string(testGUID)}})
}

func (f *fakeConn) Bind(username, password string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.bindUser, f.bindPass = username, password

	return f.bindErr
}

func (f *fakeConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.searches = append(f.searches, req)

	if req.Scope == ldap.ScopeBaseObject {
		e, ok := f.entries[strings.ToLower(req.BaseDN)]
		if !ok {
			return nil, ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("no such object"))
		}

		return &ldap.SearchResult{Entries: []*ldap.Entry{e}}, nil
	}

	if f.subtree == nil {
		return &ldap.SearchResult{}, nil
	}

	return &ldap.SearchResult{Entries: f.subtree(req)}, nil
}

func (f *fakeConn) SearchWithPaging(req *ldap.SearchRequest, _ uint32) (*ldap.SearchResult, error) {
	return f.Search(req)
}

func (f *fakeConn) Add(req *ldap.AddRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.adds = append(f.adds, req)
	f.put(req.DN)

	return nil
}

func (f *fakeConn) Modify(req *ldap.ModifyRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.modifies = append(f.modifies, req)

	return f.modifyErr[strings.ToLower(req.DN)]
}

func (f *fakeConn) Del(req *ldap.DelRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.dels = append(f.dels, req)
	delete(f.entries, strings.ToLower(req.DN))

	return nil
}

func (f *fakeConn) Close() error {
	f.closed = true

	return nil
}

func (f *fakeConn) SetTimeout(timeout time.Duration) { f.timeout = timeout }

func newTestClient(f *fakeConn) *Client {
	return &Client{conn: f, server: "dc1.vprodemo.com", baseDN: testBase, configDN: testConfig, domain: "vprodemo.com"}
}

func attrs(req *ldap.AddRequest) map[string][]string {
	out := map[string][]string{}
	for _, a := range req.Attributes {
		out[a.Type] = a.Vals
	}

	return out
}

func TestEnsureComputerNew(t *testing.T) {
	t.Parallel()

	f := newFake()
	c := newTestClient(f)

	got, err := c.EnsureComputer(context.Background(), ComputerRequest{Name: "host1", Description: "Intel(R) AMT device - x"})
	if err != nil {
		t.Fatal(err)
	}

	want := Computer{
		HostName:          "iME-host1",
		SAMAccountName:    "iME$host1$",
		DNSFQDN:           "iME-host1.vprodemo.com",
		UserPrincipalName: "iME-host1@vprodemo.com",
		DistinguishedName: "CN=iME-host1,CN=Computers,DC=vprodemo,DC=com",
		GUID:              "03020100-0504-0706-0809-0a0b0c0d0e0f",
		Password:          got.Password,
	}
	if got != want {
		t.Errorf("computer = %+v, want %+v", got, want)
	}

	if len(f.adds) != 1 {
		t.Fatalf("adds = %d", len(f.adds))
	}

	wantAttrs := map[string][]string{
		"objectClass":        {"computer"},
		"sAMAccountName":     {"iME$host1$"},
		"userAccountControl": {"69632"},
		"dNSHostName":        {"iME-host1.vprodemo.com"},
		"userPrincipalName":  {"iME-host1@vprodemo.com"},
		"description":        {"Intel(R) AMT device - x"},
	}

	gotAttrs := attrs(f.adds[0])
	for k, v := range wantAttrs {
		if !slices.Equal(gotAttrs[k], v) {
			t.Errorf("attribute %s = %v, want %v", k, gotAttrs[k], v)
		}
	}

	if len(gotAttrs) != len(wantAttrs) {
		t.Errorf("attributes = %v", gotAttrs)
	}

	if f.adds[0].DN != want.DistinguishedName {
		t.Errorf("add DN = %q", f.adds[0].DN)
	}

	if len(f.dels) != 0 {
		t.Errorf("unexpected deletes %v", f.dels)
	}
}

func TestEnsureComputerNoDescription(t *testing.T) {
	t.Parallel()

	f := newFake()

	if _, err := newTestClient(f).EnsureComputer(context.Background(), ComputerRequest{Name: "h", OU: "OU=AMT,OU=Devices"}); err != nil {
		t.Fatal(err)
	}

	if _, ok := attrs(f.adds[0])["description"]; ok {
		t.Error("description set without one")
	}

	if f.adds[0].DN != "CN=iME-h,OU=AMT,OU=Devices,DC=vprodemo,DC=com" {
		t.Errorf("DN = %q", f.adds[0].DN)
	}
}

func TestEnsureComputerExisting(t *testing.T) {
	t.Parallel()

	dn := "CN=iME-host1,CN=Computers,DC=vprodemo,DC=com"
	f := newFake(dn)

	got, err := newTestClient(f).EnsureComputer(context.Background(), ComputerRequest{Name: "host1"})
	if err != nil {
		t.Fatal(err)
	}

	if !got.AlreadyPresent {
		t.Error("AlreadyPresent = false")
	}

	if len(f.adds) != 0 {
		t.Errorf("adds = %d, want 0", len(f.adds))
	}

	if len(f.modifies) != 1 || f.modifies[0].DN != dn {
		t.Errorf("modifies = %v", f.modifies)
	}
}

func TestEnsureComputerDeletesStrays(t *testing.T) {
	t.Parallel()

	target := "CN=iME-host1,CN=Computers,DC=vprodemo,DC=com"
	stray := "CN=iME-host1,OU=Old,DC=vprodemo,DC=com"
	f := newFake(target, stray)
	f.subtree = func(req *ldap.SearchRequest) []*ldap.Entry {
		if req.Filter != "(&(objectCategory=computer)(userPrincipalName=iME-host1@vprodemo.com))" {
			t.Errorf("filter = %q", req.Filter)
		}

		if req.BaseDN != testBase || req.Scope != ldap.ScopeWholeSubtree {
			t.Errorf("search base %q scope %d", req.BaseDN, req.Scope)
		}

		// Same target DN in different case is not a stray.
		return []*ldap.Entry{ldap.NewEntry(stray, nil), ldap.NewEntry(strings.ToLower(target), nil)}
	}

	if _, err := newTestClient(f).EnsureComputer(context.Background(), ComputerRequest{Name: "host1"}); err != nil {
		t.Fatal(err)
	}

	if len(f.dels) != 1 || f.dels[0].DN != stray {
		t.Fatalf("deletes = %v", f.dels)
	}

	ctrls := f.dels[0].Controls
	if len(ctrls) != 1 {
		t.Fatalf("controls = %v", ctrls)
	}

	ctrl, ok := ctrls[0].(*ldap.ControlString)
	if !ok || ctrl.ControlType != "1.2.840.113556.1.4.805" || !ctrl.Criticality {
		t.Errorf("control = %v", ctrls[0])
	}
}

func TestEnsureComputerUnicodePwd(t *testing.T) {
	t.Parallel()

	f := newFake()

	got, err := newTestClient(f).EnsureComputer(context.Background(), ComputerRequest{Name: "host1"})
	if err != nil {
		t.Fatal(err)
	}

	if len(f.modifies) != 1 {
		t.Fatalf("modifies = %d", len(f.modifies))
	}

	change := f.modifies[0].Changes[0]
	if change.Operation != ldap.ReplaceAttribute || change.Modification.Type != "unicodePwd" {
		t.Fatalf("change = %+v", change)
	}

	var want []byte
	for _, u := range utf16.Encode([]rune(`"` + got.Password + `"`)) {
		want = append(want, byte(u), byte(u>>8))
	}

	if v := change.Modification.Vals; len(v) != 1 || !bytes.Equal([]byte(v[0]), want) {
		t.Errorf("unicodePwd = %x, want %x", v, want)
	}
}

func TestUnicodePwdKnownVector(t *testing.T) {
	t.Parallel()

	want := []byte{'"', 0, 'a', 0, 'B', 0, '1', 0, '"', 0}
	if got := []byte(unicodePwd("aB1")); !bytes.Equal(got, want) {
		t.Errorf("unicodePwd = %x, want %x", got, want)
	}
}

func TestFormatGUID(t *testing.T) {
	t.Parallel()

	got, err := formatGUID(testGUID)
	if err != nil {
		t.Fatal(err)
	}

	if got != "03020100-0504-0706-0809-0a0b0c0d0e0f" {
		t.Errorf("guid = %q", got)
	}

	if _, err := formatGUID([]byte{1, 2}); !errors.Is(err, ErrBadGUID) {
		t.Errorf("short guid err = %v", err)
	}
}

func TestGeneratePassword(t *testing.T) {
	t.Parallel()

	seen := map[string]bool{}

	for range 500 {
		p, err := generatePassword(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		if !amtPasswordOK(p) {
			t.Fatalf("password %q fails AMT rules", p)
		}

		if !strings.ContainsAny(p, "+/") || !strings.ContainsAny(p, "0123456789") ||
			strings.ToLower(p) == p || strings.ToUpper(p) == p {
			t.Fatalf("password %q missing a character class", p)
		}

		if seen[p] {
			t.Fatalf("password %q repeated", p)
		}

		seen[p] = true
	}
}

func TestAMTPasswordOK(t *testing.T) {
	t.Parallel()

	tests := map[string]bool{
		"aB3+aaaaaaaaaaaaaaaa": true,
		"aB3/aaaaaaaaaaaaaaaa": true,
		"aB3aaaaaaaaaaaaaaaaa": false, // no symbol
		"ab3+aaaaaaaaaaaaaaaa": false, // no upper
		"AB3+AAAAAAAAAAAAAAAA": false, // no lower
		"aBc+aaaaaaaaaaaaaaaa": false, // no digit
		"aB3+":                 false, // short
	}

	for p, want := range tests {
		if got := amtPasswordOK(p); got != want {
			t.Errorf("amtPasswordOK(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestGeneratePasswordReaderError(t *testing.T) {
	t.Parallel()

	if _, err := generatePassword(bytes.NewReader(nil)); err == nil {
		t.Error("want error from empty reader")
	}

	// A reader that never yields a valid password gives up.
	if _, err := generatePassword(zeroReader{}); !errors.Is(err, ErrPasswordGeneration) {
		t.Errorf("err = %v", err)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)

	return len(p), nil
}

func TestEnsureComputerGroups(t *testing.T) {
	t.Parallel()

	member := "CN=Already,CN=Users,DC=vprodemo,DC=com"
	fresh := "CN=AMT Devices,CN=Users,DC=vprodemo,DC=com"
	missing := "CN=Missing,CN=Users,DC=vprodemo,DC=com"
	f := newFake(member, fresh)
	f.modifyErr[strings.ToLower(member)] = ldap.NewError(ldap.LDAPResultEntryAlreadyExists, errors.New("already a member"))

	got, err := newTestClient(f).EnsureComputer(context.Background(),
		ComputerRequest{Name: "host1", SecurityGroups: []string{"", member, missing, fresh}})
	if err != nil {
		t.Fatal(err)
	}

	var groupNames []string

	for _, m := range f.modifies[1:] {
		groupNames = append(groupNames, m.DN)

		ch := m.Changes[0]
		if ch.Operation != ldap.AddAttribute || ch.Modification.Type != "member" ||
			!slices.Equal(ch.Modification.Vals, []string{got.DistinguishedName}) {
			t.Errorf("group change = %+v", ch)
		}
	}

	if !slices.Equal(groupNames, []string{member, fresh}) {
		t.Errorf("groups modified = %v", groupNames)
	}
}

func TestEnsureComputerGroupError(t *testing.T) {
	t.Parallel()

	group := "CN=G,DC=vprodemo,DC=com"
	f := newFake(group)
	f.modifyErr[strings.ToLower(group)] = ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("denied"))

	_, err := newTestClient(f).EnsureComputer(context.Background(), ComputerRequest{Name: "h", SecurityGroups: []string{group}})
	if !ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights) {
		t.Errorf("err = %v", err)
	}
}

func TestEnsureComputerAttributeOrValueExists(t *testing.T) {
	t.Parallel()

	group := "CN=G,DC=vprodemo,DC=com"
	f := newFake(group)
	f.modifyErr[strings.ToLower(group)] = ldap.NewError(ldap.LDAPResultAttributeOrValueExists, errors.New("exists"))

	if _, err := newTestClient(f).EnsureComputer(context.Background(), ComputerRequest{Name: "h", SecurityGroups: []string{group}}); err != nil {
		t.Errorf("err = %v", err)
	}
}

func TestEnsureComputerFilterEscaping(t *testing.T) {
	t.Parallel()

	f := newFake()

	var filter string

	f.subtree = func(req *ldap.SearchRequest) []*ldap.Entry {
		filter = req.Filter

		return nil
	}

	got, err := newTestClient(f).EnsureComputer(context.Background(), ComputerRequest{Name: "a*b)c,d"})
	if err != nil {
		t.Fatal(err)
	}

	if want := `(&(objectCategory=computer)(userPrincipalName=iME-a\2ab\29c,d@vprodemo.com))`; filter != want {
		t.Errorf("filter = %q, want %q", filter, want)
	}

	if want := `CN=iME-a*b)c\,d,CN=Computers,DC=vprodemo,DC=com`; got.DistinguishedName != want {
		t.Errorf("DN = %q, want %q", got.DistinguishedName, want)
	}
}

func TestEnsureComputerErrors(t *testing.T) {
	t.Parallel()

	c := newTestClient(newFake())

	if _, err := c.EnsureComputer(context.Background(), ComputerRequest{}); !errors.Is(err, ErrNoName) {
		t.Errorf("empty name err = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := c.EnsureComputer(ctx, ComputerRequest{Name: "x"}); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled err = %v", err)
	}
}

func TestRemoveComputer(t *testing.T) {
	t.Parallel()

	dn := "CN=iME-host1,OU=AMT,DC=vprodemo,DC=com"
	f := newFake(dn)
	c := newTestClient(f)

	removed, err := c.RemoveComputer(context.Background(), "host1", "OU=AMT")
	if err != nil || !removed {
		t.Fatalf("removed = %v, err = %v", removed, err)
	}

	if len(f.dels) != 1 || f.dels[0].DN != dn || len(f.dels[0].Controls) != 1 {
		t.Errorf("deletes = %v", f.dels)
	}

	removed, err = c.RemoveComputer(context.Background(), "host1", "OU=AMT")
	if err != nil || removed {
		t.Errorf("second remove = %v, err = %v", removed, err)
	}

	removed, err = c.RemoveComputer(context.Background(), "other", "")
	if err != nil || removed {
		t.Errorf("absent remove = %v, err = %v", removed, err)
	}
}

func TestContainers(t *testing.T) {
	t.Parallel()

	f := newFake()
	f.subtree = func(req *ldap.SearchRequest) []*ldap.Entry {
		if req.Filter != "(|(objectCategory=organizationalUnit)(objectCategory=container))" {
			t.Errorf("filter = %q", req.Filter)
		}

		return []*ldap.Entry{
			ldap.NewEntry("OU=AMT,OU=Devices,DC=vprodemo,DC=com", nil),
			ldap.NewEntry(testBase, nil),
			ldap.NewEntry("CN=Computers,dc=VPRODEMO,dc=com", nil),
			ldap.NewEntry("CN=Elsewhere,DC=other,DC=com", nil),
		}
	}

	got, err := newTestClient(f).Containers(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if want := []string{"CN=Computers", "OU=AMT,OU=Devices"}; !slices.Equal(got, want) {
		t.Errorf("containers = %v, want %v", got, want)
	}
}

func TestSecurityGroups(t *testing.T) {
	t.Parallel()

	f := newFake()
	f.subtree = func(req *ldap.SearchRequest) []*ldap.Entry {
		if req.Filter != "(&(objectCategory=group)(groupType:1.2.840.113556.1.4.803:=2147483648))" {
			t.Errorf("filter = %q", req.Filter)
		}

		return []*ldap.Entry{ldap.NewEntry("CN=B,DC=vprodemo,DC=com", nil), ldap.NewEntry("CN=A,DC=vprodemo,DC=com", nil)}
	}

	got, err := newTestClient(f).SecurityGroups(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if want := []string{"CN=A,DC=vprodemo,DC=com", "CN=B,DC=vprodemo,DC=com"}; !slices.Equal(got, want) {
		t.Errorf("groups = %v", got)
	}
}

func TestCertificateAuthorities(t *testing.T) {
	t.Parallel()

	f := newFake()
	f.subtree = func(req *ldap.SearchRequest) []*ldap.Entry {
		if req.BaseDN != "CN=Enrollment Services,CN=Public Key Services,CN=Services,"+testConfig {
			t.Errorf("base = %q", req.BaseDN)
		}

		if req.Filter != "(objectCategory=pKIEnrollmentService)" {
			t.Errorf("filter = %q", req.Filter)
		}

		return []*ldap.Entry{
			ldap.NewEntry("CN=vprodemo-CA,...", map[string][]string{
				"cn": {"vprodemo-CA"}, "dNSHostName": {"ca1.vprodemo.com"},
				"certificateTemplates": {"AMT8021X", "WebServer"}, "cACertificate": {"\x30\x82\x00\xff"},
			}),
			ldap.NewEntry("CN=A-CA,...", map[string][]string{"cn": {"A-CA"}, "dNSHostName": {"ca0.vprodemo.com"}}),
		}
	}

	got, err := newTestClient(f).CertificateAuthorities(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 2 || got[0].Name != "A-CA" || len(got[0].Templates) != 0 {
		t.Fatalf("CAs = %+v", got)
	}

	ca := got[1]
	if ca.Name != "vprodemo-CA" || ca.Host != "ca1.vprodemo.com" ||
		!slices.Equal(ca.Templates, []string{"AMT8021X", "WebServer"}) ||
		!bytes.Equal(ca.Certificate, []byte{0x30, 0x82, 0x00, 0xff}) {
		t.Errorf("CA = %+v", ca)
	}
}

func TestDialRejectsEmptyPassword(t *testing.T) {
	t.Parallel()

	_, err := Dial(context.Background(), Config{Server: "192.0.2.1", BindUsername: "svc@vprodemo.com"})
	if !errors.Is(err, ErrNoBindPassword) {
		t.Errorf("err = %v", err)
	}

	_, err = Dial(context.Background(), Config{Server: "192.0.2.1", BindPassword: "x"})
	if !errors.Is(err, ErrNoBindUsername) {
		t.Errorf("err = %v", err)
	}
}

func TestDialWithFake(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      Config
		wantHost string
		wantPort string
	}{
		{"server with port", Config{Server: "dc1.vprodemo.com:3269"}, "dc1.vprodemo.com", "3269"},
		{"server without port", Config{Server: "dc1.vprodemo.com"}, "dc1.vprodemo.com", "636"},
		{"SRV discovery", Config{Domain: "vprodemo.com"}, "dc2.vprodemo.com", "636"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newFake()
			cfg := tc.cfg
			cfg.BindUsername, cfg.BindPassword = "svc@vprodemo.com", "secret"

			var gotHost, gotPort string

			d := fakeDialer(t, f, &gotHost, &gotPort)

			c, err := d.dial(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}

			if gotHost != tc.wantHost || gotPort != tc.wantPort || c.ServerName() != tc.wantHost {
				t.Errorf("dialed %s:%s, server %s", gotHost, gotPort, c.ServerName())
			}

			checkBound(t, c, f)
		})
	}
}

func fakeDialer(t *testing.T, f *fakeConn, host, port *string) dialer {
	t.Helper()

	return dialer{
		lookupSRV: func(_ context.Context, service, proto, name string) (string, []*net.SRV, error) {
			if service != "ldap" || proto != "tcp" || name != "dc._msdcs.vprodemo.com" {
				t.Errorf("SRV lookup %s %s %s", service, proto, name)
			}

			return "", []*net.SRV{{Target: "dc2.vprodemo.com.", Port: 389}}, nil
		},
		open: func(h, p string, _ Config, _ time.Duration) (conn, error) {
			*host, *port = h, p

			return f, nil
		},
	}
}

func checkBound(t *testing.T, c *Client, f *fakeConn) {
	t.Helper()

	if f.bindUser != "svc@vprodemo.com" || f.bindPass != "secret" || f.timeout != defaultTimeout {
		t.Errorf("bind %s/%s timeout %v", f.bindUser, f.bindPass, f.timeout)
	}

	if c.BaseDN() != testBase || c.DomainName() != "vprodemo.com" || c.configDN != testConfig {
		t.Errorf("base %q domain %q config %q", c.BaseDN(), c.DomainName(), c.configDN)
	}

	if err := c.Close(); err != nil || !f.closed {
		t.Errorf("close err %v closed %v", err, f.closed)
	}
}

func TestDialBindFailureCloses(t *testing.T) {
	t.Parallel()

	f := newFake()
	f.bindErr = ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials"))

	d := dialer{open: func(string, string, Config, time.Duration) (conn, error) { return f, nil }}

	_, err := d.dial(context.Background(), Config{Server: "dc", BindUsername: "u", BindPassword: "p"})
	if !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) || !f.closed {
		t.Errorf("err = %v, closed = %v", err, f.closed)
	}
}

func TestDialNoServer(t *testing.T) {
	t.Parallel()

	_, err := Dial(context.Background(), Config{BindUsername: "u", BindPassword: "p"})
	if !errors.Is(err, ErrNoServer) {
		t.Errorf("err = %v", err)
	}
}

func TestDomainFromDN(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"DC=vprodemo,DC=com":        "vprodemo.com",
		"dc=Corp,DC=Example,DC=org": "corp.example.org",
		"OU=x,DC=a,DC=b":            "a.b",
		"not a dn":                  "",
	}

	for dn, want := range tests {
		if got := domainFromDN(dn); got != want {
			t.Errorf("domainFromDN(%q) = %q, want %q", dn, got, want)
		}
	}
}
