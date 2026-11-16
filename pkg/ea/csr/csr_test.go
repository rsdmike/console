package csr_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"unicode/utf16"

	"github.com/device-management-toolkit/console/pkg/ea/csr"
)

var (
	keyOnce sync.Once
	testKey *rsa.PrivateKey
)

func key(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	keyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}

		testKey = k
	})

	return testKey
}

func spki(t *testing.T) []byte {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(&key(t).PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	return der
}

func fullRequest(t *testing.T) csr.Request {
	t.Helper()

	return csr.Request{
		SubjectDN: "CN=iME-x,CN=Computers,DC=vprodemo,DC=com",
		PublicKey: spki(t),
		Template:  "AMT8021X",
		Names: csr.Names{
			DNS: []string{"iME-x.vprodemo.com", "iME-x"},
			UPN: []string{"iME-x@vprodemo.com", "HTTP/iME-x.vprodemo.com:16992"},
			URI: []string{"LDAP://CN=iME-x,CN=Computers,DC=vprodemo,DC=com"},
		},
	}
}

var (
	oidSAN      = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidTemplate = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2}
	oidUPN      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
	oidDC       = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
)

func parse(t *testing.T, r csr.Request) *x509.CertificateRequest {
	t.Helper()

	der, err := csr.BuildNullSigned(r)
	if err != nil {
		t.Fatal(err)
	}

	req, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}

	return req
}

func TestBuildNullSignedRoundTrip(t *testing.T) {
	t.Parallel()

	req := parse(t, fullRequest(t))

	if req.SignatureAlgorithm != x509.SHA256WithRSA {
		t.Errorf("signature algorithm = %v", req.SignatureAlgorithm)
	}

	if len(req.Signature) != 0 {
		t.Errorf("signature = %x, want empty", req.Signature)
	}

	// DER order is least specific first: DC=com first, CN=iME-x last.
	want := []string{"DC=com", "DC=vprodemo", "CN=Computers", "CN=iME-x"}
	if got := derSubject(req); !slices.Equal(got, want) {
		t.Errorf("subject = %v, want %v", got, want)
	}

	if want := []string{"iME-x.vprodemo.com", "iME-x"}; !slices.Equal(req.DNSNames, want) {
		t.Errorf("DNSNames = %v", req.DNSNames)
	}

	if len(req.URIs) != 1 || !strings.EqualFold(req.URIs[0].String(), "LDAP://CN=iME-x,CN=Computers,DC=vprodemo,DC=com") {
		t.Errorf("URIs = %v", req.URIs)
	}

	pub, ok := req.PublicKey.(*rsa.PublicKey)
	if !ok || !pub.Equal(&key(t).PublicKey) {
		t.Error("public key differs")
	}
}

func TestBuildNullSignedExtensions(t *testing.T) {
	t.Parallel()

	req := parse(t, fullRequest(t))

	upns := upnsFromSAN(t, extension(t, req, oidSAN))
	if want := []string{"iME-x@vprodemo.com", "HTTP/iME-x.vprodemo.com:16992"}; !slices.Equal(upns, want) {
		t.Errorf("UPNs = %v", upns)
	}

	if got := templateName(t, extension(t, req, oidTemplate)); got != "AMT8021X" {
		t.Errorf("template = %q", got)
	}
}

func TestBuildNullSignedPKCS1Key(t *testing.T) {
	t.Parallel()

	r := fullRequest(t)
	r.PublicKey = x509.MarshalPKCS1PublicKey(&key(t).PublicKey)

	der, err := csr.BuildNullSigned(r)
	if err != nil {
		t.Fatal(err)
	}

	req, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}

	pub, ok := req.PublicKey.(*rsa.PublicKey)
	if !ok || !pub.Equal(&key(t).PublicKey) {
		t.Error("public key differs")
	}
}

func TestBuildNullSignedNoExtensions(t *testing.T) {
	t.Parallel()

	der, err := csr.BuildNullSigned(csr.Request{SubjectDN: "CN=iME-host.vprodemo.com", PublicKey: spki(t)})
	if err != nil {
		t.Fatal(err)
	}

	req, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}

	if len(req.Extensions) != 0 || len(req.DNSNames) != 0 {
		t.Errorf("extensions = %v, DNSNames = %v", req.Extensions, req.DNSNames)
	}

	if req.Subject.CommonName != "iME-host.vprodemo.com" {
		t.Errorf("CN = %q", req.Subject.CommonName)
	}
}

func TestBuildNullSignedTemplateOnly(t *testing.T) {
	t.Parallel()

	der, err := csr.BuildNullSigned(csr.Request{SubjectDN: "CN=x", PublicKey: spki(t), Template: "Web Server"})
	if err != nil {
		t.Fatal(err)
	}

	req, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}

	if len(req.Extensions) != 1 {
		t.Fatalf("extensions = %v", req.Extensions)
	}

	if got := templateName(t, extension(t, req, oidTemplate)); got != "Web Server" {
		t.Errorf("template = %q", got)
	}
}

func TestEncodeWithSignature(t *testing.T) {
	t.Parallel()

	sig := make([]byte, 256)

	der, err := csr.Encode(fullRequest(t), sig)
	if err != nil {
		t.Fatal(err)
	}

	req, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}

	if len(req.Signature) != 256 {
		t.Errorf("signature length = %d", len(req.Signature))
	}
}

func TestBuildNullSignedSubjectEncoding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		dn   string
		want []string // DER order
		tag  int      // tag of the CN value
	}{
		{"escaped comma", `CN=Doe\, John,O=Intel`, []string{"O=Intel", "CN=Doe, John"}, asn1.TagPrintableString},
		{"hex escape", `CN=a\2Cb`, []string{"CN=a,b"}, asn1.TagPrintableString},
		{"spaces and case", ` cn = host , ou=AMT , dc=example`, []string{"DC=example", "OU=AMT", "CN=host"}, asn1.TagPrintableString},
		{"non-printable value", "CN=iME$abc$,C=US,ST=AZ,L=Chandler", []string{"L=Chandler", "ST=AZ", "C=US", "CN=iME$abc$"}, asn1.TagUTF8String},
		{"utf8 value", "CN=Grüße", []string{"CN=Grüße"}, asn1.TagUTF8String},
		{"dotted oid", "2.5.4.3=dotted", []string{"CN=dotted"}, asn1.TagPrintableString},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := parse(t, csr.Request{SubjectDN: tc.dn, PublicKey: spki(t)})

			if got := derSubject(req); !slices.Equal(got, tc.want) {
				t.Errorf("subject = %q, want %q", got, tc.want)
			}

			if got := valueTag(t, req, asn1.ObjectIdentifier{2, 5, 4, 3}); got != tc.tag {
				t.Errorf("CN tag = %d, want %d", got, tc.tag)
			}
		})
	}
}

func TestBuildNullSignedValueTags(t *testing.T) {
	t.Parallel()

	req := parse(t, csr.Request{SubjectDN: "CN=x,C=US,DC=com", PublicKey: spki(t)})

	if got := valueTag(t, req, oidDC); got != asn1.TagIA5String {
		t.Errorf("DC tag = %d", got)
	}

	if got := valueTag(t, req, asn1.ObjectIdentifier{2, 5, 4, 6}); got != asn1.TagPrintableString {
		t.Errorf("C tag = %d", got)
	}
}

var shortNames = map[string]string{
	"2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
	"2.5.4.10": "O", "2.5.4.11": "OU", "0.9.2342.19200300.100.1.25": "DC",
}

// derSubject lists the subject attributes in DER order as TYPE=value.
func derSubject(req *x509.CertificateRequest) []string {
	out := make([]string, 0, len(req.Subject.Names))

	for _, n := range req.Subject.Names {
		out = append(out, fmt.Sprintf("%s=%v", shortNames[n.Type.String()], n.Value))
	}

	return out
}

type rawATV struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

type rawRDNSET []rawATV

func valueTag(t *testing.T, req *x509.CertificateRequest, oid asn1.ObjectIdentifier) int {
	t.Helper()

	var rdns []rawRDNSET
	if _, err := asn1.Unmarshal(req.RawSubject, &rdns); err != nil {
		t.Fatal(err)
	}

	for _, rdn := range rdns {
		for _, atv := range rdn {
			if atv.Type.Equal(oid) {
				return atv.Value.Tag
			}
		}
	}

	t.Fatalf("attribute %v not found", oid)

	return 0
}

func TestBuildNullSignedErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mod  func(r *csr.Request)
		want error
	}{
		{"empty key", func(r *csr.Request) { r.PublicKey = nil }, csr.ErrEmptyPublicKey},
		{"garbage key", func(r *csr.Request) { r.PublicKey = []byte{1, 2, 3, 4} }, csr.ErrInvalidPublicKey},
		{"empty DN", func(r *csr.Request) { r.SubjectDN = "  " }, csr.ErrEmptySubject},
		{"no equals", func(r *csr.Request) { r.SubjectDN = "CN=x,Computers" }, csr.ErrMalformedSubject},
		{"empty value", func(r *csr.Request) { r.SubjectDN = "CN=,DC=com" }, csr.ErrMalformedSubject},
		{"empty type", func(r *csr.Request) { r.SubjectDN = "=x" }, csr.ErrMalformedSubject},
		{"trailing comma", func(r *csr.Request) { r.SubjectDN = "CN=x," }, csr.ErrMalformedSubject},
		{"unknown type", func(r *csr.Request) { r.SubjectDN = "XX=x" }, csr.ErrMalformedSubject},
		{"trailing backslash", func(r *csr.Request) { r.SubjectDN = `CN=x\` }, csr.ErrMalformedSubject},
		{"non-ascii DC", func(r *csr.Request) { r.SubjectDN = "CN=x,DC=bé" }, csr.ErrNotIA5},
		{"non-ascii DNS", func(r *csr.Request) { r.Names.DNS = []string{"hé"} }, csr.ErrNotIA5},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := fullRequest(t)
			tc.mod(&r)

			_, err := csr.BuildNullSigned(r)
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func extension(t *testing.T, req *x509.CertificateRequest, oid asn1.ObjectIdentifier) []byte {
	t.Helper()

	for _, e := range req.Extensions {
		if e.Id.Equal(oid) {
			return e.Value
		}
	}

	t.Fatalf("extension %v not found", oid)

	return nil
}

func upnsFromSAN(t *testing.T, san []byte) []string {
	t.Helper()

	var names []asn1.RawValue
	if _, err := asn1.Unmarshal(san, &names); err != nil {
		t.Fatal(err)
	}

	var upns []string

	for _, n := range names {
		if n.Class != asn1.ClassContextSpecific || n.Tag != 0 {
			continue
		}

		var other struct {
			ID    asn1.ObjectIdentifier
			Value asn1.RawValue
		}

		if _, err := asn1.UnmarshalWithParams(n.FullBytes, &other, "tag:0"); err != nil {
			t.Fatal(err)
		}

		if !other.ID.Equal(oidUPN) {
			t.Errorf("otherName type = %v", other.ID)
		}

		// other.Value is the [0] EXPLICIT wrapper around the UTF8String.
		var inner asn1.RawValue
		if _, err := asn1.Unmarshal(other.Value.Bytes, &inner); err != nil {
			t.Fatal(err)
		}

		if other.Value.Class != asn1.ClassContextSpecific || inner.Tag != asn1.TagUTF8String {
			t.Errorf("UPN wrapper class %d, inner tag %d", other.Value.Class, inner.Tag)
		}

		upns = append(upns, string(inner.Bytes))
	}

	return upns
}

func templateName(t *testing.T, value []byte) string {
	t.Helper()

	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(value, &raw); err != nil {
		t.Fatal(err)
	}

	if raw.Tag != asn1.TagBMPString || len(raw.Bytes)%2 != 0 {
		t.Fatalf("template value tag %d len %d", raw.Tag, len(raw.Bytes))
	}

	units := make([]uint16, 0, len(raw.Bytes)/2)
	for i := 0; i < len(raw.Bytes); i += 2 {
		units = append(units, uint16(raw.Bytes[i])<<8|uint16(raw.Bytes[i+1]))
	}

	return string(utf16.Decode(units))
}
