// Package ea serves the legacy Enterprise Assistant HTTP contract rpc-go
// uses (--eaAddress <console>/ea): /api/authenticate/:guid and
// /api/configure/{profile,keypair,csr}/:guid.
package ea

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	dto "github.com/device-management-toolkit/console/internal/entity/dto/v2"
	"github.com/device-management-toolkit/console/internal/usecase/enterpriseassistant"
	"github.com/device-management-toolkit/console/pkg/logger"
)

const (
	// MaxBodyBytes bounds every /ea request body.
	MaxBodyBytes = 1 << 20

	tokenLifetime = 60 * time.Minute
	keyBytes      = 32
	claimDeviceID = "deviceId"
	bearerPrefix  = "Bearer"

	statusUnauthorized = "Unauthorized"
	statusInvalidToken = "Invalid Token"
	statusGUIDMismatch = "GUID Mismatch"
	statusNotEndpoint  = "Not a valid endpoint"
	statusError        = "Error"
)

// Routes holds the /ea handlers.
type Routes struct {
	uc  enterpriseassistant.Feature
	l   logger.Interface
	key []byte
	now func() time.Time
}

// statusBody is the legacy EA error/status body.
type statusBody struct {
	Status  string `json:"status"`
	Details string `json:"details,omitempty"`
}

type authRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type authResponse struct {
	JWTToken string `json:"jwtToken"`
}

// NewRoutes mounts the EA endpoints on handler (the /ea group). Tokens are
// signed with a random per-process key, never auth.jwtKey, so an EA token
// cannot pass Console's API middleware.
func NewRoutes(handler *gin.RouterGroup, uc enterpriseassistant.Feature, l logger.Interface) *Routes {
	key := make([]byte, keyBytes)
	_, _ = rand.Read(key) // crypto/rand.Read never returns an error since Go 1.24.

	r := &Routes{uc: uc, l: l, key: key, now: time.Now}

	g := handler.Group("", r.requireEnabled, limitBody)
	g.POST("/api/authenticate/:guid", r.authenticate)

	c := g.Group("/api/configure", r.requireToken)
	c.POST("/profile/:guid", r.configure(uc.Profile))
	c.POST("/keypair/:guid", r.configure(uc.KeyPair))
	c.POST("/csr/:guid", r.configure(uc.CSR))
	c.DELETE("/:guid", r.remove)

	return r
}

// requireEnabled answers 404 while ea.enabled is false (checked per request).
func (r *Routes) requireEnabled(c *gin.Context) {
	if !r.uc.DeviceAccess().Enabled {
		c.AbortWithStatusJSON(http.StatusNotFound, statusBody{Status: statusNotEndpoint})

		return
	}

	c.Next()
}

func limitBody(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, MaxBodyBytes)
	c.Next()
}

// equal compares in constant time regardless of length.
func equal(a, b string) bool {
	ha, hb := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))

	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

func (r *Routes) authenticate(c *gin.Context) {
	guid := c.Param("guid")
	access := r.uc.DeviceAccess()

	var req authRequest
	if err := c.ShouldBindJSON(&req); err != nil || access.Username == "" || access.Password == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, statusBody{Status: statusUnauthorized})

		return
	}

	userOK := equal(req.Username, access.Username)
	passOK := equal(req.Password, access.Password)

	if !userOK || !passOK {
		r.l.Warn("ea: authentication failed for device " + guid)
		c.AbortWithStatusJSON(http.StatusUnauthorized, statusBody{Status: statusUnauthorized})

		return
	}

	token, err := r.issue(guid)
	if err != nil {
		r.l.Error(err, "ea: signing token")
		c.AbortWithStatusJSON(http.StatusInternalServerError, statusBody{Status: statusError, Details: "Error processing request"})

		return
	}

	c.JSON(http.StatusOK, authResponse{JWTToken: token})
}

func (r *Routes) issue(guid string) (string, error) {
	now := r.now()
	claims := jwt.MapClaims{
		claimDeviceID: guid,
		"iat":         now.Unix(),
		"exp":         now.Add(tokenLifetime).Unix(),
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(r.key)
	if err != nil {
		return "", fmt.Errorf("ea.issue: %w", err)
	}

	return signed, nil
}

// requireToken checks the bearer token and that its deviceId is the :guid.
func (r *Routes) requireToken(c *gin.Context) {
	header := c.GetHeader("Authorization")
	if !strings.HasPrefix(header, bearerPrefix) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, statusBody{Status: statusUnauthorized})

		return
	}

	raw := strings.TrimSpace(strings.TrimPrefix(header, bearerPrefix))

	claims := jwt.MapClaims{}

	_, err := jwt.ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) { return r.key, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(r.now))

	deviceID, ok := claims[claimDeviceID].(string)
	if err != nil || !ok || deviceID == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, statusBody{Status: statusInvalidToken})

		return
	}

	if !strings.EqualFold(deviceID, c.Param("guid")) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, statusBody{Status: statusGUIDMismatch})

		return
	}

	c.Next()
}

type deviceCall func(ctx context.Context, req dto.EADeviceRequest) (dto.EADeviceResponse, error)

func (r *Routes) configure(call deviceCall) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req dto.EADeviceRequest
		if !r.bind(c, &req, false) {
			return
		}

		resp, err := call(c.Request.Context(), req)
		if err != nil {
			r.fail(c, err)

			return
		}

		c.JSON(http.StatusOK, resp)
	}
}

func (r *Routes) remove(c *gin.Context) {
	var req dto.EADeviceRequest
	if !r.bind(c, &req, true) {
		return
	}

	if req.NodeID == "" {
		req.NodeID = c.Param("guid")
	}

	res, err := r.uc.Remove(c.Request.Context(), req)
	if err != nil {
		r.fail(c, err)

		return
	}

	c.JSON(http.StatusOK, res)
}

// bind decodes the JSON body; an empty body is allowed only when optional.
func (r *Routes) bind(c *gin.Context, req *dto.EADeviceRequest, optional bool) bool {
	err := c.ShouldBindJSON(req)
	if err == nil || (optional && errors.Is(err, io.EOF)) {
		return true
	}

	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, statusBody{Status: statusError, Details: "Request body too large"})

		return false
	}

	c.AbortWithStatusJSON(http.StatusBadRequest, statusBody{Status: statusError, Details: "Validation failed: request body is not valid JSON."})

	return false
}

// fail maps use-case errors: validation 400, AD/CA 502, anything else 500.
func (r *Routes) fail(c *gin.Context, err error) {
	status := http.StatusInternalServerError

	switch {
	case errors.Is(err, enterpriseassistant.ErrValidation):
		status = http.StatusBadRequest
	case errors.Is(err, enterpriseassistant.ErrUpstream):
		status = http.StatusBadGateway
	}

	if status != http.StatusBadRequest {
		r.l.Error(err, "ea: "+c.FullPath())
	}

	c.AbortWithStatusJSON(status, statusBody{Status: statusError, Details: err.Error()})
}
