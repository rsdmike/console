// Package csr builds the unsigned ("null-signed") PKCS#10 certificate
// requests that Intel AMT signs with a key it generated
// (AMT_PublicKeyManagementService.GeneratePKCS10RequestEx).
//
// It replaces CertEnroll's CX509CertificateRequestPkcs10.InitializeFromPublicKey
// as used by the .NET Enterprise Assistant.
package csr

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
)

// ErrNotImplemented marks skeleton functions not written yet.
var ErrNotImplemented = errors.New("csr: not implemented")

// Errors returned (wrapped) by BuildNullSigned and Encode.
var (
	ErrEmptySubject     = errors.New("csr: empty subject DN")
	ErrMalformedSubject = errors.New("csr: malformed subject DN")
	ErrEmptyPublicKey   = errors.New("csr: empty public key")
	ErrInvalidPublicKey = errors.New("csr: public key is neither SubjectPublicKeyInfo nor PKCS#1")
	ErrNotIA5           = errors.New("csr: value is not ASCII (IA5String)")
)

// Names are the Subject Alternative Names to put in the request.
type Names struct {
	// DNS become dNSName entries.
	DNS []string
	// UPN become otherName entries of type 1.3.6.1.4.1.311.20.2.3 (UTF8String).
	// AMT service principal names (HTTP/host.domain:16992 ...) also go here,
	// as the .NET EA did.
	UPN []string
	// URI become uniformResourceIdentifier entries, e.g. "LDAP://CN=iME-x,CN=Computers,DC=vprodemo,DC=com".
	URI []string
}

// Request describes the certificate request.
type Request struct {
	// SubjectDN is the subject as a comma-separated DN, most specific first,
	// e.g. "CN=iME-host.vprodemo.com" or "CN=iME-x,CN=Computers,DC=vprodemo,DC=com".
	// CN, OU, O, L, ST, C and DC (domainComponent) attributes are supported.
	SubjectDN string
	// PublicKey is the AMT key pair's public key: either a DER
	// SubjectPublicKeyInfo or a DER PKCS#1 RSAPublicKey (AMT's DERKey).
	PublicKey []byte
	// Template is the certificate template name; when set it is added as the
	// szOID_ENROLL_CERTTYPE_EXTENSION (1.3.6.1.4.1.311.20.2, BMPString).
	Template string
	Names    Names
}

// OIDs used in the request.
var (
	oidSHA256WithRSA    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
	oidSubjectAltName   = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidEnrollCertType   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2}
	oidUPN              = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
)

// attributeTypes maps the supported DN attribute names to OIDs.
var attributeTypes = map[string]asn1.ObjectIdentifier{
	"CN": {2, 5, 4, 3},
	"C":  {2, 5, 4, 6},
	"L":  {2, 5, 4, 7},
	"ST": {2, 5, 4, 8},
	"O":  {2, 5, 4, 10},
	"OU": {2, 5, 4, 11},
	"DC": {0, 9, 2342, 19200300, 100, 1, 25},
}

// GeneralName context tags (RFC 5280).
const (
	tagOtherName = 0
	tagDNSName   = 2
	tagURI       = 6
)

const (
	bitsPerByte  = 8
	bytesPerUnit = 2 // UTF-16 code unit
	maxASCII     = 0x7f
)

// BuildNullSigned returns the DER PKCS#10 request with a
// sha256WithRSAEncryption algorithm identifier and an empty signature,
// ready for GeneratePKCS10RequestEx.
func BuildNullSigned(req Request) ([]byte, error) {
	return Encode(req, nil)
}

// Encode returns the DER PKCS#10 request with a sha256WithRSAEncryption
// algorithm identifier and signature as the signature BIT STRING. A nil
// signature gives the null-signed request of BuildNullSigned; callers can
// pass a zero-filled signature of the key size if AMT rejects an empty one.
func Encode(req Request, signature []byte) ([]byte, error) {
	cri, err := encodeCRI(req)
	if err != nil {
		return nil, err
	}

	algo, err := asn1.Marshal(struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue
	}{oidSHA256WithRSA, asn1.NullRawValue})
	if err != nil {
		return nil, fmt.Errorf("csr.Encode: %w", err)
	}

	sig, err := asn1.Marshal(asn1.BitString{Bytes: signature, BitLength: len(signature) * bitsPerByte})
	if err != nil {
		return nil, fmt.Errorf("csr.Encode: %w", err)
	}

	return marshalConstructed(asn1.TagSequence, cri, algo, sig)
}

// encodeCRI encodes the CertificationRequestInfo.
func encodeCRI(req Request) ([]byte, error) {
	name, err := encodeName(req.SubjectDN)
	if err != nil {
		return nil, err
	}

	spki, err := subjectPublicKeyInfo(req.PublicKey)
	if err != nil {
		return nil, err
	}

	attrs, err := encodeAttributes(req)
	if err != nil {
		return nil, err
	}

	version, err := asn1.Marshal(0)
	if err != nil {
		return nil, fmt.Errorf("csr.encodeCRI: %w", err)
	}

	return marshalConstructed(asn1.TagSequence, version, name, spki, attrs)
}

// subjectPublicKeyInfo returns key as a DER SubjectPublicKeyInfo.
func subjectPublicKeyInfo(key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, ErrEmptyPublicKey
	}

	if _, err := x509.ParsePKIXPublicKey(key); err == nil {
		return key, nil
	}

	pub, err := x509.ParsePKCS1PublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPublicKey, err)
	}

	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("csr.subjectPublicKeyInfo: %w", err)
	}

	return spki, nil
}

// encodeAttributes returns the [0] IMPLICIT SET OF Attribute holding one
// extensionRequest attribute, or an empty set when there is no extension.
func encodeAttributes(req Request) ([]byte, error) {
	exts, err := encodeExtensions(req)
	if err != nil {
		return nil, err
	}

	var attr []byte

	if exts != nil {
		extensions, err := marshalConstructed(asn1.TagSequence, exts)
		if err != nil {
			return nil, err
		}

		values, err := marshalConstructed(asn1.TagSet, extensions)
		if err != nil {
			return nil, err
		}

		oid, err := asn1.Marshal(oidExtensionRequest)
		if err != nil {
			return nil, fmt.Errorf("csr.encodeAttributes: %w", err)
		}

		attr, err = marshalConstructed(asn1.TagSequence, oid, values)
		if err != nil {
			return nil, err
		}
	}

	out, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: attr})
	if err != nil {
		return nil, fmt.Errorf("csr.encodeAttributes: %w", err)
	}

	return out, nil
}

// encodeExtensions returns the concatenated Extension encodings, nil when none.
func encodeExtensions(req Request) ([]byte, error) {
	var exts []byte

	san, err := encodeSAN(req.Names)
	if err != nil {
		return nil, err
	}

	if san != nil {
		ext, err := marshalExtension(oidSubjectAltName, san)
		if err != nil {
			return nil, err
		}

		exts = append(exts, ext...)
	}

	if req.Template != "" {
		bmp, err := asn1.Marshal(asn1.RawValue{Tag: asn1.TagBMPString, Bytes: bmpBytes(req.Template)})
		if err != nil {
			return nil, fmt.Errorf("csr.encodeExtensions: %w", err)
		}

		ext, err := marshalExtension(oidEnrollCertType, bmp)
		if err != nil {
			return nil, err
		}

		exts = append(exts, ext...)
	}

	return exts, nil
}

// encodeSAN returns the DER GeneralNames, or nil when names is empty.
// Order follows the .NET EA: URIs, DNS names, then UPNs.
func encodeSAN(names Names) ([]byte, error) {
	var body []byte

	for _, uri := range names.URI {
		gn, err := ia5GeneralName(tagURI, uri)
		if err != nil {
			return nil, err
		}

		body = append(body, gn...)
	}

	for _, dns := range names.DNS {
		gn, err := ia5GeneralName(tagDNSName, dns)
		if err != nil {
			return nil, err
		}

		body = append(body, gn...)
	}

	for _, upn := range names.UPN {
		gn, err := upnGeneralName(upn)
		if err != nil {
			return nil, err
		}

		body = append(body, gn...)
	}

	if body == nil {
		return nil, nil
	}

	return marshalConstructed(asn1.TagSequence, body)
}

func ia5GeneralName(tag int, s string) ([]byte, error) {
	if !isASCII(s) {
		return nil, fmt.Errorf("%w: %q", ErrNotIA5, s)
	}

	out, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, Bytes: []byte(s)})
	if err != nil {
		return nil, fmt.Errorf("csr.ia5GeneralName: %w", err)
	}

	return out, nil
}

// upnGeneralName encodes otherName { 1.3.6.1.4.1.311.20.2.3, [0] EXPLICIT UTF8String }.
func upnGeneralName(upn string) ([]byte, error) {
	oid, err := asn1.Marshal(oidUPN)
	if err != nil {
		return nil, fmt.Errorf("csr.upnGeneralName: %w", err)
	}

	utf8, err := asn1.Marshal(asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte(upn)})
	if err != nil {
		return nil, fmt.Errorf("csr.upnGeneralName: %w", err)
	}

	value, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: utf8})
	if err != nil {
		return nil, fmt.Errorf("csr.upnGeneralName: %w", err)
	}

	body := append(oid, value...) //nolint:gocritic // oid is a fresh slice we own

	out, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tagOtherName, IsCompound: true, Bytes: body})
	if err != nil {
		return nil, fmt.Errorf("csr.upnGeneralName: %w", err)
	}

	return out, nil
}

// marshalExtension encodes Extension { extnID, extnValue } (critical omitted, DEFAULT FALSE).
func marshalExtension(oid asn1.ObjectIdentifier, value []byte) ([]byte, error) {
	out, err := asn1.Marshal(struct {
		ID    asn1.ObjectIdentifier
		Value []byte
	}{oid, value})
	if err != nil {
		return nil, fmt.Errorf("csr.marshalExtension: %w", err)
	}

	return out, nil
}

// bmpBytes returns s as UTF-16BE (BMPString contents).
func bmpBytes(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(units)*bytesPerUnit)

	for _, u := range units {
		out = append(out, byte(u>>bitsPerByte), byte(u&0xff)) //nolint:mnd // low byte mask
	}

	return out
}

func marshalConstructed(tag int, parts ...[]byte) ([]byte, error) {
	var body []byte

	for _, p := range parts {
		body = append(body, p...)
	}

	out, err := asn1.Marshal(asn1.RawValue{Tag: tag, IsCompound: true, Bytes: body})
	if err != nil {
		return nil, fmt.Errorf("csr.marshalConstructed: %w", err)
	}

	return out, nil
}

// encodeName encodes the DN string as an X.501 Name. The string lists the
// most specific RDN first; the DER lists it last.
func encodeName(dn string) ([]byte, error) {
	if strings.TrimSpace(dn) == "" {
		return nil, ErrEmptySubject
	}

	components, err := splitDN(dn)
	if err != nil {
		return nil, err
	}

	var rdns []byte

	for i := len(components) - 1; i >= 0; i-- {
		atv, err := encodeATV(components[i])
		if err != nil {
			return nil, err
		}

		set, err := marshalConstructed(asn1.TagSet, atv)
		if err != nil {
			return nil, err
		}

		rdns = append(rdns, set...)
	}

	return marshalConstructed(asn1.TagSequence, rdns)
}

type component struct {
	typ   string
	value string
}

// dnScanner splits a DN string into components.
type dnScanner struct {
	out     []component
	value   strings.Builder
	raw     strings.Builder // component text as written, for errors
	typ     string
	haveTyp bool
}

func (s *dnScanner) flush() error {
	value := strings.TrimSpace(s.value.String())
	if !s.haveTyp || s.typ == "" || value == "" {
		return fmt.Errorf("%w: component %q", ErrMalformedSubject, s.raw.String())
	}

	s.out = append(s.out, component{typ: s.typ, value: value})
	s.value.Reset()
	s.raw.Reset()

	s.typ, s.haveTyp = "", false

	return nil
}

// splitDN splits dn on unescaped commas and unescapes values (a backslash
// followed by two hex digits or by any one character).
func splitDN(dn string) ([]component, error) {
	var s dnScanner

	for i := 0; i < len(dn); i++ {
		c := dn[i]

		switch {
		case c == '\\':
			n, err := s.escape(dn, i)
			if err != nil {
				return nil, err
			}

			i += n
		case c == ',':
			if err := s.flush(); err != nil {
				return nil, err
			}
		case c == '=' && !s.haveTyp:
			s.typ = strings.ToUpper(strings.TrimSpace(s.value.String()))
			s.haveTyp = true

			s.value.Reset()
			s.raw.WriteByte(c)
		default:
			s.value.WriteByte(c)
			s.raw.WriteByte(c)
		}
	}

	if err := s.flush(); err != nil {
		return nil, err
	}

	return s.out, nil
}

// escape handles the backslash at dn[i] and returns how many extra bytes it consumed.
func (s *dnScanner) escape(dn string, i int) (int, error) {
	if i+1 >= len(dn) {
		return 0, fmt.Errorf("%w: trailing backslash", ErrMalformedSubject)
	}

	if b, ok := hexPair(dn, i+1); ok {
		s.value.WriteByte(b)
		s.raw.WriteString(dn[i : i+3])

		return 2, nil //nolint:mnd // two hex digits
	}

	s.value.WriteByte(dn[i+1])
	s.raw.WriteString(dn[i : i+2])

	return 1, nil
}

func hexPair(s string, i int) (byte, bool) {
	if i+1 >= len(s) {
		return 0, false
	}

	hi, ok1 := hexDigit(s[i])
	lo, ok2 := hexDigit(s[i+1])

	if !ok1 || !ok2 {
		return 0, false
	}

	return hi<<4 | lo, true
}

func hexDigit(c byte) (byte, bool) {
	const ten = 10

	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + ten, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + ten, true
	default:
		return 0, false
	}
}

// encodeATV encodes AttributeTypeAndValue. C uses PrintableString and DC
// IA5String; the others use PrintableString when the value fits and
// UTF8String otherwise. A dotted OID is accepted as the type.
func encodeATV(c component) ([]byte, error) {
	oid, ok := attributeTypes[c.typ]
	if !ok {
		parsed, err := parseOID(c.typ)
		if err != nil {
			return nil, fmt.Errorf("%w: unsupported attribute type %q", ErrMalformedSubject, c.typ)
		}

		oid = parsed
	}

	tag := asn1.TagUTF8String

	switch c.typ {
	case "DC":
		if !isASCII(c.value) {
			return nil, fmt.Errorf("%w: DC=%q", ErrNotIA5, c.value)
		}

		tag = asn1.TagIA5String
	case "C":
		if !isPrintable(c.value) {
			return nil, fmt.Errorf("%w: C=%q is not a PrintableString", ErrMalformedSubject, c.value)
		}

		tag = asn1.TagPrintableString
	default:
		if isPrintable(c.value) {
			tag = asn1.TagPrintableString
		}
	}

	out, err := asn1.Marshal(struct {
		Type  asn1.ObjectIdentifier
		Value asn1.RawValue
	}{oid, asn1.RawValue{Tag: tag, Bytes: []byte(c.value)}})
	if err != nil {
		return nil, fmt.Errorf("csr.encodeATV: %w", err)
	}

	return out, nil
}

func parseOID(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(s, ".")
	if len(parts) < 2 { //nolint:mnd // an OID has at least two arcs
		return nil, ErrMalformedSubject
	}

	oid := make(asn1.ObjectIdentifier, 0, len(parts))

	for _, p := range parts {
		if p == "" {
			return nil, ErrMalformedSubject
		}

		n := 0

		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return nil, ErrMalformedSubject
			}

			n = n*10 + int(p[i]-'0') //nolint:mnd // decimal digits
		}

		oid = append(oid, n)
	}

	return oid, nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > maxASCII {
			return false
		}
	}

	return true
}

// isPrintable reports whether s fits an ASN.1 PrintableString.
func isPrintable(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]

		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte(" '()+,-./:=?", c) >= 0:
		default:
			return false
		}
	}

	return true
}
