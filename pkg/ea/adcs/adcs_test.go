package adcs

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
)

func utf16le(s string) []byte {
	var out []byte
	for _, u := range utf16.Encode([]rune(s)) {
		out = append(out, byte(u), byte(u>>8))
	}

	return out
}

func TestTemplateAttributes(t *testing.T) {
	t.Parallel()

	got := templateAttributes("AMT8021X")
	want := utf16le("CertificateTemplate:AMT8021X\x00")

	if !bytes.Equal(got, want) {
		t.Errorf("attributes = %x, want %x", got, want)
	}

	if len(got) != (len("CertificateTemplate:AMT8021X")+1)*2 || got[len(got)-1] != 0 || got[len(got)-2] != 0 {
		t.Errorf("attributes are not NUL-terminated UTF-16LE: %x", got)
	}

	if templateAttributes("") != nil {
		t.Error("empty template should give no attributes")
	}

	b := blob(got)
	if int(b.Length) != len(got) || !bytes.Equal(b.Buffer, got) {
		t.Errorf("blob = %+v", b)
	}

	if e := blob(nil); e.Length != 0 || e.Buffer != nil {
		t.Errorf("empty blob = %+v", e)
	}
}

func TestDecodeUTF16(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{"terminated", append(utf16le("Denied by Policy Module\x00"), 'x', 0), "Denied by Policy Module"},
		{"unterminated", utf16le("Issued"), "Issued"},
		{"odd length", append(utf16le("ok"), 'z'), "ok"},
		{"non-ascii", utf16le("Zertifikat ausgestellt ✓\x00"), "Zertifikat ausgestellt ✓"},
		{"empty", nil, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := decodeUTF16(tc.in); got != tc.want {
				t.Errorf("decodeUTF16 = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFiletime(t *testing.T) {
	t.Parallel()

	epoch := filetime(time.Unix(0, 0))
	if epoch.HighDateTime != 0x019DB1DE || epoch.LowDateTime != 0xD53E8000 {
		t.Errorf("unix epoch = %08x%08x, want 019db1ded53e8000", epoch.HighDateTime, epoch.LowDateTime)
	}

	when := time.Date(2026, 11, 16, 12, 30, 45, 123456700, time.UTC)
	ft := filetime(when)
	ticks := uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime)

	if want := uint64(when.Unix()+11644473600)*10_000_000 + 1234567; ticks != want {
		t.Errorf("ticks = %d, want %d", ticks, want)
	}

	if ft := filetime(time.Time{}); !ft.IsZero() {
		t.Errorf("zero time = %+v, want zero FILETIME", ft)
	}

	if ft := filetime(time.Date(1500, 1, 1, 0, 0, 0, 0, time.UTC)); *ft != (dtyp.Filetime{}) {
		t.Errorf("pre-1601 = %+v, want clamped to zero", ft)
	}
}

func TestDispositionError(t *testing.T) {
	t.Parallel()

	rpcErr := errors.New("rpc failure")

	tests := []struct {
		name        string
		res         Result
		callErr     error
		notIssued   bool
		wantNil     bool
		wantContain []string
	}{
		{"issued", Result{Disposition: DispositionIssued}, nil, false, true, nil},
		{
			"denied with message",
			Result{Disposition: DispositionDenied, RequestID: 42, Message: "Denied by Policy Module "},
			nil, true, false,
			[]string{"request 42", "denied", "Denied by Policy Module"},
		},
		{"pending without message", Result{Disposition: DispositionUnderSubmission, RequestID: 7}, nil, true, false, []string{"pending"}},
		{"error with call error", Result{Disposition: DispositionError}, rpcErr, true, false, []string{"rpc failure"}},
		{"issued but call error", Result{Disposition: DispositionIssued}, rpcErr, false, false, []string{"rpc failure"}},
		{"unknown disposition", Result{Disposition: 99}, nil, true, false, []string{"disposition 99"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := dispositionError(tc.res, tc.callErr)
			if tc.wantNil {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}

				return
			}

			checkDispositionErr(t, err, tc.callErr, tc.notIssued, tc.wantContain)
		})
	}
}

func checkDispositionErr(t *testing.T, err, callErr error, notIssued bool, contain []string) {
	t.Helper()

	if err == nil {
		t.Fatal("err = nil")
	}

	if errors.Is(err, ErrNotIssued) != notIssued {
		t.Errorf("errors.Is(ErrNotIssued) = %v, want %v (%v)", !notIssued, notIssued, err)
	}

	if callErr != nil && !errors.Is(err, callErr) {
		t.Errorf("call error not wrapped: %v", err)
	}

	for _, s := range contain {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("err %q does not contain %q", err, s)
		}
	}
}

func submitErr(ctx context.Context, cfg Config, csrDER []byte) error {
	_, err := New(cfg).Submit(ctx, csrDER, "T")

	return err
}

func validConfig() Config {
	return Config{Host: "ca1.vprodemo.com", CAName: "vprodemo-CA", Domain: "vprodemo.com", Username: "svc-ea", Password: "x", Timeout: 2 * time.Second}
}

func TestValidation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	noHost := validConfig()
	noHost.Host = ""

	noCA := validConfig()
	noCA.CAName = ""

	noPass := validConfig()
	noPass.Password = ""

	tests := []struct {
		name string
		call func() error
		want error
	}{
		{"submit empty csr", func() error { return submitErr(ctx, validConfig(), nil) }, ErrEmptyRequest},
		{"submit no CA", func() error { return submitErr(ctx, noCA, []byte{1}) }, ErrNoCAName},
		{"submit no host", func() error { return submitErr(ctx, noHost, []byte{1}) }, ErrNoHost},
		{"revoke negative reason", func() error { return New(validConfig()).Revoke(ctx, "1a", -1, time.Now()) }, ErrBadReason},
		{"ping no password", func() error { return New(noPass).Ping(ctx) }, ErrNoCredentials},
		{"revoke bad serial", func() error { return New(validConfig()).Revoke(ctx, "12:ab", ReasonSuperseded, time.Now()) }, ErrBadSerial},
		{"revoke empty serial", func() error { return New(validConfig()).Revoke(ctx, "", ReasonSuperseded, time.Now()) }, ErrBadSerial},
		{"revoke no CA", func() error { return New(noCA).Revoke(ctx, "1a2b", ReasonSuperseded, time.Now()) }, ErrNoCAName},
		{"revoke no password", func() error { return New(noPass).Revoke(ctx, "1a2b", ReasonSuperseded, time.Now()) }, ErrNoCredentials},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if err := tc.call(); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestDefaultTimeout(t *testing.T) {
	t.Parallel()

	if c := New(Config{}); c.cfg.Timeout != defaultTimeout {
		t.Errorf("timeout = %v", c.cfg.Timeout)
	}
}

func TestCredentialDomain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		user, domain, wantUser, wantDomain string
	}{
		{"svc-ea", "vprodemo.com", "svc-ea", "vprodemo.com"},
		{"svc-ea@vprodemo.com", "", "svc-ea", "vprodemo.com"},
		{`VPRODEMO\svc-ea`, "vprodemo.com", "svc-ea", "VPRODEMO"},
	}

	for _, tc := range tests {
		c := New(Config{Username: tc.user, Domain: tc.domain, Password: "p"})

		cred := c.credential()
		if cred.UserName() != tc.wantUser || cred.DomainName() != tc.wantDomain {
			t.Errorf("%s/%s -> %s\\%s, want %s\\%s", tc.user, tc.domain, cred.DomainName(), cred.UserName(), tc.wantDomain, tc.wantUser)
		}
	}
}

// closedPort returns a 127.0.0.1 port with nothing listening.
func closedPort(t *testing.T) string {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	port := portOf(t, l)
	_ = l.Close()

	return port
}

func portOf(t *testing.T, l net.Listener) string {
	t.Helper()

	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	return port
}

// silentServer accepts connections and never answers.
func silentServer(t *testing.T) string {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	var (
		mu    sync.Mutex
		conns []net.Conn
	)

	t.Cleanup(func() {
		_ = l.Close()

		mu.Lock()
		defer mu.Unlock()

		for _, c := range conns {
			_ = c.Close()
		}
	})

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}

			mu.Lock()

			conns = append(conns, c)
			mu.Unlock()
		}
	}()

	return portOf(t, l)
}

func TestUnreachableCA(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		port func(t *testing.T) string
		call func(c *Client) error
	}{
		{"ping refused", closedPort, func(c *Client) error { return c.Ping(context.Background()) }},
		{"submit refused", closedPort, func(c *Client) error {
			_, err := c.Submit(context.Background(), []byte{0x30, 0}, "AMT8021X")

			return err
		}},
		{"ping silent", silentServer, func(c *Client) error { return c.Ping(context.Background()) }},
		{"submit silent", silentServer, func(c *Client) error {
			_, err := c.Submit(context.Background(), []byte{0x30, 0}, "AMT8021X")

			return err
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := validConfig()
			cfg.Host = "127.0.0.1"
			c := New(cfg)
			c.icprEndpoint = "127.0.0.1[" + tc.port(t) + "]"

			start := time.Now()

			err := tc.call(c)
			if err == nil {
				t.Fatal("want an error")
			}

			if elapsed := time.Since(start); elapsed > cfg.Timeout+3*time.Second {
				t.Errorf("took %v, timeout %v", elapsed, cfg.Timeout)
			}
		})
	}
}
