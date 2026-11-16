package v2

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"

	dto "github.com/device-management-toolkit/console/internal/entity/dto/v2"
	"github.com/device-management-toolkit/console/internal/usecase/enterpriseassistant"
	"github.com/device-management-toolkit/console/pkg/logger"
)

// eaMaxBodyBytes bounds settings request bodies.
const eaMaxBodyBytes = 1 << 20

type enterpriseAssistantRoutes struct {
	uc enterpriseassistant.Feature
	l  logger.Interface
}

type eaError struct {
	Error string `json:"error"`
}

// NewEnterpriseAssistantRoutes mounts the EA settings API under
// <handler>/admin/enterprise-assistant.
func NewEnterpriseAssistantRoutes(handler *gin.RouterGroup, uc enterpriseassistant.Feature, l logger.Interface) {
	r := &enterpriseAssistantRoutes{uc: uc, l: l}

	h := handler.Group("/admin/enterprise-assistant")
	{
		h.GET("/settings", r.getSettings)
		h.PUT("/settings", r.putSettings)
		h.POST("/test", r.test)
		h.GET("/ad/containers", r.containers)
		h.GET("/ad/groups", r.groups)
		h.GET("/ca/authorities", r.authorities)
	}
}

func (r *enterpriseAssistantRoutes) getSettings(c *gin.Context) {
	c.JSON(http.StatusOK, r.uc.GetSettings(c.Request.Context()))
}

func (r *enterpriseAssistantRoutes) putSettings(c *gin.Context) {
	in, ok := r.decode(c, false)
	if !ok {
		return
	}

	out, err := r.uc.UpdateSettings(c.Request.Context(), *in)
	if err != nil {
		r.fail(c, err)

		return
	}

	c.JSON(http.StatusOK, out)
}

func (r *enterpriseAssistantRoutes) test(c *gin.Context) {
	in, ok := r.decode(c, true)
	if !ok {
		return
	}

	out, err := r.uc.TestSettings(c.Request.Context(), in)
	if err != nil {
		r.fail(c, err)

		return
	}

	c.JSON(http.StatusOK, out)
}

func (r *enterpriseAssistantRoutes) containers(c *gin.Context) {
	out, err := r.uc.Containers(c.Request.Context())
	if err != nil {
		r.fail(c, err)

		return
	}

	c.JSON(http.StatusOK, out)
}

func (r *enterpriseAssistantRoutes) groups(c *gin.Context) {
	out, err := r.uc.SecurityGroups(c.Request.Context())
	if err != nil {
		r.fail(c, err)

		return
	}

	c.JSON(http.StatusOK, out)
}

func (r *enterpriseAssistantRoutes) authorities(c *gin.Context) {
	out, err := r.uc.Authorities(c.Request.Context())
	if err != nil {
		r.fail(c, err)

		return
	}

	c.JSON(http.StatusOK, out)
}

// decode reads a settings body. With optional, an empty body yields nil.
func (r *enterpriseAssistantRoutes) decode(c *gin.Context, optional bool) (*dto.EASettings, bool) {
	raw, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, eaMaxBodyBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, eaError{Error: "request body too large"})

			return nil, false
		}

		c.AbortWithStatusJSON(http.StatusBadRequest, eaError{Error: "cannot read request body"})

		return nil, false
	}

	if optional && len(bytes.TrimSpace(raw)) == 0 {
		return nil, true
	}

	var in dto.EASettings
	if err := json.Unmarshal(raw, &in); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, eaError{Error: "invalid settings body: " + err.Error()})

		return nil, false
	}

	return &in, true
}

// fail maps use-case errors: bad input and missing configuration 400,
// AD/CA failures 502, anything else 500.
func (r *enterpriseAssistantRoutes) fail(c *gin.Context, err error) {
	status := http.StatusInternalServerError

	switch {
	case errors.Is(err, enterpriseassistant.ErrValidation), errors.Is(err, enterpriseassistant.ErrNotConfigured):
		status = http.StatusBadRequest
	case errors.Is(err, enterpriseassistant.ErrUpstream):
		status = http.StatusBadGateway
	}

	if status != http.StatusBadRequest {
		r.l.Error(err, "http - v2 - enterprise assistant")
	}

	c.AbortWithStatusJSON(status, eaError{Error: err.Error()})
}
