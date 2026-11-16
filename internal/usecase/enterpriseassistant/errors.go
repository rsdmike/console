package enterpriseassistant

import (
	"errors"
	"fmt"
)

// Sentinel errors the controllers map to HTTP status codes. Match with errors.Is.
var (
	// ErrNotConfigured: the AD or CA settings needed for the call are missing.
	ErrNotConfigured = errors.New("enterprise assistant: not configured")
	// ErrValidation: the request or the settings are invalid (400).
	ErrValidation = errors.New("enterprise assistant: validation failed")
	// ErrUpstream: Active Directory or the CA failed or refused (502).
	ErrUpstream = errors.New("enterprise assistant: upstream failure")
)

var (
	errADNotConfigured = kindError{kind: ErrNotConfigured, msg: "enterprise assistant: active directory is not configured"}
	errCANotConfigured = kindError{kind: ErrNotConfigured, msg: "enterprise assistant: certificate authority is not configured"}
)

// kindError carries a caller-facing message and matches one sentinel.
type kindError struct {
	kind error
	msg  string
}

func (e kindError) Error() string { return e.msg }

func (e kindError) Is(target error) bool { return target == e.kind }

func validationError(msg string) error { return kindError{kind: ErrValidation, msg: msg} }

// upstream wraps an AD or CA failure so errors.Is(err, ErrUpstream) holds
// while the library error stays reachable.
func upstream(op string, err error) error {
	return fmt.Errorf("%w: %s: %w", ErrUpstream, op, err)
}
