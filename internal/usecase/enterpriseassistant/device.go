package enterpriseassistant

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	dto "github.com/device-management-toolkit/console/internal/entity/dto/v2"
	"github.com/device-management-toolkit/console/pkg/ea/ad"
	"github.com/device-management-toolkit/console/pkg/ea/adcs"
)

// Wire values of the legacy satellite protocol.
const (
	authProtocolEAPTLS = 0
	authProtocolPEAP   = 2

	satelliteAction = "satellite"
	satelliteFlags  = 2

	subActionProfileCompleted = "Profile-Completed"
	subActionKeyPairRequest   = "KeyPair-Request"
	subActionCSRRequest       = "CSR-Request"

	midpointDivisor = 2
)

func envelope(req *dto.EADeviceRequest, subAction string, body dto.EADeviceResponseBody) dto.EADeviceResponse {
	return dto.EADeviceResponse{
		EADeviceRequest: *req,
		Action:          satelliteAction,
		SatelliteFlags:  satelliteFlags,
		SubAction:       subAction,
		Response:        body,
	}
}

func intPtr(v int) *int { return &v }

func blank(s string) bool { return strings.TrimSpace(s) == "" }

// validate reproduces the .NET EA request models' IsValid messages.
func validate(rules ...string) error {
	var failed []string

	for _, r := range rules {
		if r != "" {
			failed = append(failed, r)
		}
	}

	if len(failed) == 0 {
		return nil
	}

	return validationError("Validation failed: " + strings.Join(failed, ", "))
}

func rule(bad bool, msg string) string {
	if bad {
		return msg
	}

	return ""
}

func nodeIDRule(req *dto.EADeviceRequest) string {
	return rule(blank(req.NodeID), "Nodeid is required.")
}

func eapTLSRule(req *dto.EADeviceRequest) string {
	return rule(req.AuthProtocol != authProtocolEAPTLS, "AuthProtocol must be 0")
}

func decodeBase64(field, value string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, validationError("Validation failed: " + field + " is not valid base64.")
	}

	return b, nil
}

func (uc *UseCase) ensureComputer(ctx context.Context, dir Directory, s snapshot, req *dto.EADeviceRequest) (ad.Computer, error) {
	creq := computerRequest(&s.ea, req)

	computer, err := dir.EnsureComputer(ctx, creq)
	if err != nil {
		return ad.Computer{}, upstream("active directory: add computer "+creq.Name, err)
	}

	if computer.AlreadyPresent {
		uc.log.Info("enterpriseassistant: reset computer " + creq.Name)
	} else {
		uc.log.Info("enterpriseassistant: added computer " + creq.Name)
	}

	return computer, nil
}

func domainName(dir Directory, s snapshot) string {
	if d := dir.DomainName(); d != "" {
		return d
	}

	return s.ea.AD.Domain
}

func b64(der []byte) string {
	if len(der) == 0 {
		return ""
	}

	return base64.StdEncoding.EncodeToString(der)
}

// Profile answers /api/configure/profile: PEAP gets the computer account,
// EAP-TLS reuses a still-fresh certificate or asks AMT for a key pair.
func (uc *UseCase) Profile(ctx context.Context, req dto.EADeviceRequest) (dto.EADeviceResponse, error) {
	if err := validate(nodeIDRule(&req), rule(req.AuthProtocol != authProtocolEAPTLS && req.AuthProtocol != authProtocolPEAP,
		"AuthProtocol must be 0 or 2.")); err != nil {
		return dto.EADeviceResponse{}, err
	}

	s := uc.snapshot()

	if req.AuthProtocol == authProtocolEAPTLS && !caConfigured(&s.ea) {
		return dto.EADeviceResponse{}, errCANotConfigured
	}

	dir, err := uc.dial(ctx, &s.ea)
	if err != nil {
		return dto.EADeviceResponse{}, err
	}
	defer uc.closeDir(dir)

	root, err := uc.rootCert(ctx, dir, s)
	if err != nil {
		return dto.EADeviceResponse{}, err
	}

	if req.AuthProtocol == authProtocolPEAP {
		return uc.completeProfile(ctx, dir, s, &req, root, "")
	}

	old, reusable := uc.existingCert(&req, root)
	if reusable {
		return uc.completeProfile(ctx, dir, s, &req, root, req.CertID)
	}

	if old != nil {
		uc.revoke(ctx, s, old)
	}

	return envelope(&req, subActionKeyPairRequest, dto.EADeviceResponseBody{}), nil
}

// completeProfile ensures the computer and returns its credentials.
func (uc *UseCase) completeProfile(ctx context.Context, dir Directory, s snapshot, req *dto.EADeviceRequest, root []byte, certID string) (dto.EADeviceResponse, error) {
	computer, err := uc.ensureComputer(ctx, dir, s, req)
	if err != nil {
		return dto.EADeviceResponse{}, err
	}

	return envelope(req, subActionProfileCompleted, dto.EADeviceResponseBody{
		AuthProtocol: intPtr(req.AuthProtocol),
		Domain:       domainName(dir, s),
		Username:     computer.SAMAccountName,
		Password:     computer.Password,
		RootCert:     b64(root),
		CertID:       certID,
	}), nil
}

// existingCert parses the certificate AMT already holds (cert+certid). It is
// reusable when now is between NotBefore and the validity midpoint and its
// issuer is the CA certificate's subject. The parsed certificate is returned
// even when not reusable so it can be revoked.
func (uc *UseCase) existingCert(req *dto.EADeviceRequest, rootDER []byte) (*x509.Certificate, bool) {
	if req.Cert == "" || req.CertID == "" {
		return nil, false
	}

	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.Cert))
	if err != nil {
		return nil, false
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, false
	}

	now := uc.now()
	midpoint := cert.NotBefore.Add(cert.NotAfter.Sub(cert.NotBefore) / midpointDivisor)

	if !now.After(cert.NotBefore) || !now.Before(midpoint) {
		return cert, false
	}

	root := parseRoot(rootDER)
	if root == nil || !bytes.Equal(cert.RawIssuer, root.RawSubject) {
		return cert, false
	}

	return cert, true
}

// revoke is best effort: a failure is logged, never returned.
func (uc *UseCase) revoke(ctx context.Context, s snapshot, cert *x509.Certificate) {
	serial := strings.ToUpper(hex.EncodeToString(cert.SerialNumber.Bytes()))

	err := uc.caFactory(caConfig(&s.ea)).Revoke(ctx, serial, adcs.ReasonCessationOfOperation, uc.now())
	if err != nil {
		uc.log.Warn(fmt.Sprintf("enterpriseassistant: revoking certificate %s: %v", serial, err))

		return
	}

	uc.log.Info("enterpriseassistant: revoked certificate " + serial)
}

// KeyPair answers /api/configure/keypair with the null-signed CSR AMT must sign.
func (uc *UseCase) KeyPair(ctx context.Context, req dto.EADeviceRequest) (dto.EADeviceResponse, error) {
	if err := validate(nodeIDRule(&req), eapTLSRule(&req),
		rule(blank(req.DERKey), "DERKey is required."),
		rule(blank(req.KeyInstanceID), "KeyInstanceId is required.")); err != nil {
		return dto.EADeviceResponse{}, err
	}

	publicKey, err := decodeBase64("DERKey", req.DERKey)
	if err != nil {
		return dto.EADeviceResponse{}, err
	}

	s := uc.snapshot()
	if !caConfigured(&s.ea) {
		return dto.EADeviceResponse{}, errCANotConfigured
	}

	dir, err := uc.dial(ctx, &s.ea)
	if err != nil {
		return dto.EADeviceResponse{}, err
	}
	defer uc.closeDir(dir)

	computer, err := uc.ensureComputer(ctx, dir, s, &req)
	if err != nil {
		return dto.EADeviceResponse{}, err
	}

	der, err := uc.csrBuilder(csrRequest(&s.ea, &computer, publicKey))
	if err != nil {
		return dto.EADeviceResponse{}, fmt.Errorf("enterpriseassistant.KeyPair: build csr: %w", err)
	}

	return envelope(&req, subActionCSRRequest, dto.EADeviceResponseBody{
		CSR:           base64.StdEncoding.EncodeToString(der),
		KeyInstanceID: req.KeyInstanceID,
	}), nil
}

// CSR answers /api/configure/csr: submit the AMT-signed request and return
// the issued certificate.
func (uc *UseCase) CSR(ctx context.Context, req dto.EADeviceRequest) (dto.EADeviceResponse, error) {
	if err := validate(nodeIDRule(&req), eapTLSRule(&req),
		rule(blank(req.SignedCSR), "Signedcsr is required.")); err != nil {
		return dto.EADeviceResponse{}, err
	}

	signed, err := decodeBase64("Signedcsr", req.SignedCSR)
	if err != nil {
		return dto.EADeviceResponse{}, err
	}

	s := uc.snapshot()
	if !caConfigured(&s.ea) {
		return dto.EADeviceResponse{}, errCANotConfigured
	}

	dir, err := uc.dial(ctx, &s.ea)
	if err != nil {
		return dto.EADeviceResponse{}, err
	}
	defer uc.closeDir(dir)

	result, err := uc.caFactory(caConfig(&s.ea)).Submit(ctx, signed, s.ea.CA.Template)
	if err != nil {
		return dto.EADeviceResponse{}, upstream("certificate authority: submit", err)
	}

	if result.Disposition != adcs.DispositionIssued || len(result.Certificate) == 0 {
		return dto.EADeviceResponse{}, upstream(fmt.Sprintf("certificate authority: request %d disposition %d %q",
			result.RequestID, result.Disposition, result.Message), adcs.ErrNotIssued)
	}

	computer, err := uc.ensureComputer(ctx, dir, s, &req)
	if err != nil {
		return dto.EADeviceResponse{}, err
	}

	root, err := uc.rootCert(ctx, dir, s)
	if err != nil {
		return dto.EADeviceResponse{}, err
	}

	return envelope(&req, subActionProfileCompleted, dto.EADeviceResponseBody{
		AuthProtocol: intPtr(authProtocolEAPTLS),
		Certificate:  b64(result.Certificate),
		RootCert:     b64(root),
		Domain:       domainName(dir, s),
		Username:     computer.SAMAccountName,
	}), nil
}

// Remove deletes the device's computer object.
func (uc *UseCase) Remove(ctx context.Context, req dto.EADeviceRequest) (dto.EARemoveResult, error) {
	if err := validate(nodeIDRule(&req)); err != nil {
		return dto.EARemoveResult{}, err
	}

	s := uc.snapshot()

	dir, err := uc.dial(ctx, &s.ea)
	if err != nil {
		return dto.EARemoveResult{}, err
	}
	defer uc.closeDir(dir)

	name := computerName(&s.ea, &req)

	removed, err := dir.RemoveComputer(ctx, name, s.ea.AD.ComputerOU)
	if err != nil {
		return dto.EARemoveResult{}, upstream("active directory: remove computer "+name, err)
	}

	return dto.EARemoveResult{Status: "Success", Removed: removed}, nil
}
