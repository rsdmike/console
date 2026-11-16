// Package csr builds the unsigned ("null-signed") PKCS#10 certificate
// requests that Intel AMT signs with a key it generated
// (AMT_PublicKeyManagementService.GeneratePKCS10RequestEx).
//
// It replaces CertEnroll's CX509CertificateRequestPkcs10.InitializeFromPublicKey
// as used by the .NET Enterprise Assistant.
package csr

import "errors"

// ErrNotImplemented marks skeleton functions not written yet.
var ErrNotImplemented = errors.New("csr: not implemented")

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

// BuildNullSigned returns the DER PKCS#10 request with a
// sha256WithRSAEncryption algorithm identifier and an empty signature,
// ready for GeneratePKCS10RequestEx.
func BuildNullSigned(_ Request) ([]byte, error) {
	return nil, ErrNotImplemented
}
