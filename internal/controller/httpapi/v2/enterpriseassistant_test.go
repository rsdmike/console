package v2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	dtov2 "github.com/device-management-toolkit/console/internal/entity/dto/v2"
	"github.com/device-management-toolkit/console/internal/usecase/enterpriseassistant"
	"github.com/device-management-toolkit/console/pkg/logger"
)

// eaFakeFeature is a hand-written enterpriseassistant.Feature.
type eaFakeFeature struct {
	mu sync.Mutex

	settings dtov2.EASettings
	test     dtov2.EATestResult
	list     []string
	cas      []dtov2.EAAuthority
	err      error

	updated []dtov2.EASettings
	tested  []*dtov2.EASettings
}

func (f *eaFakeFeature) DeviceAccess() enterpriseassistant.DeviceAccess {
	return enterpriseassistant.DeviceAccess{}
}

func (f *eaFakeFeature) Profile(context.Context, dtov2.EADeviceRequest) (dtov2.EADeviceResponse, error) {
	return dtov2.EADeviceResponse{}, nil
}

func (f *eaFakeFeature) KeyPair(context.Context, dtov2.EADeviceRequest) (dtov2.EADeviceResponse, error) {
	return dtov2.EADeviceResponse{}, nil
}

func (f *eaFakeFeature) CSR(context.Context, dtov2.EADeviceRequest) (dtov2.EADeviceResponse, error) {
	return dtov2.EADeviceResponse{}, nil
}

func (f *eaFakeFeature) Remove(context.Context, dtov2.EADeviceRequest) (dtov2.EARemoveResult, error) {
	return dtov2.EARemoveResult{}, nil
}

func (f *eaFakeFeature) GetSettings(context.Context) dtov2.EASettings { return f.settings }

func (f *eaFakeFeature) UpdateSettings(_ context.Context, in dtov2.EASettings) (dtov2.EASettings, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.updated = append(f.updated, in)

	return f.settings, f.err
}

func (f *eaFakeFeature) TestSettings(_ context.Context, in *dtov2.EASettings) (dtov2.EATestResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.tested = append(f.tested, in)

	return f.test, f.err
}

func (f *eaFakeFeature) Containers(context.Context) ([]string, error)     { return f.list, f.err }
func (f *eaFakeFeature) SecurityGroups(context.Context) ([]string, error) { return f.list, f.err }

func (f *eaFakeFeature) Authorities(context.Context) ([]dtov2.EAAuthority, error) {
	return f.cas, f.err
}

type eaKindErr struct {
	msg string
	is  error
}

func (e eaKindErr) Error() string        { return e.msg }
func (e eaKindErr) Is(target error) bool { return target == e.is }

func eaEngine(f *eaFakeFeature) *gin.Engine {
	engine := gin.New()
	NewEnterpriseAssistantRoutes(engine.Group("/api/v2"), f, logger.New("error"))

	return engine
}

func eaDo(engine *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/api/v2/admin/enterprise-assistant"+path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	return w
}

func sampleSettings() dtov2.EASettings {
	return dtov2.EASettings{
		Enabled: true, URL: "https://console.vprodemo.com:8181/ea", Username: "eauser", PasswordSet: true, DeviceNameType: "hostname",
		ActiveDirectory: dtov2.EAActiveDirectory{
			Domain: "vprodemo.com", Server: "dc1.vprodemo.com:636", BindUsername: "svc-ea@vprodemo.com", BindPasswordSet: true,
			ComputerOU: "CN=Computers", SecurityGroups: []string{"CN=AMT Devices,CN=Users,DC=vprodemo,DC=com"},
		},
		CertificateAuthority: dtov2.EACertificateAuthority{
			Host: "ca1.vprodemo.com", Name: "vprodemo-CA", Template: "AMT8021X", CommonName: "dnsfqdn",
			AltNames: []string{"distinguishedname", "dnsfqdn", "hostname", "userprincipalname", "samaccountname", "uuid"},
		},
	}
}

// contractSettingsJSON is the GET example from Contract B.
const contractSettingsJSON = `{
  "enabled": true,
  "url": "https://console.vprodemo.com:8181/ea",
  "username": "eauser",
  "password": "",
  "passwordSet": true,
  "deviceNameType": "hostname",
  "activeDirectory": {
    "domain": "vprodemo.com",
    "server": "dc1.vprodemo.com:636",
    "bindUsername": "svc-ea@vprodemo.com",
    "bindPassword": "",
    "bindPasswordSet": true,
    "computerOU": "CN=Computers",
    "securityGroups": ["CN=AMT Devices,CN=Users,DC=vprodemo,DC=com"],
    "insecureSkipVerify": false
  },
  "certificateAuthority": {
    "host": "ca1.vprodemo.com",
    "name": "vprodemo-CA",
    "template": "AMT8021X",
    "commonName": "dnsfqdn",
    "altNames": ["distinguishedname", "dnsfqdn", "hostname", "userprincipalname", "samaccountname", "uuid"]
  }
}`

func TestEASettingsRoutes(t *testing.T) {
	t.Parallel()

	t.Run("GET settings has the contract shape", func(t *testing.T) {
		t.Parallel()

		w := eaDo(eaEngine(&eaFakeFeature{settings: sampleSettings()}), http.MethodGet, "/settings", "")
		require.Equal(t, http.StatusOK, w.Code)
		require.JSONEq(t, contractSettingsJSON, w.Body.String())
	})

	t.Run("PUT settings decodes the contract shape and returns the saved settings", func(t *testing.T) {
		t.Parallel()

		f := &eaFakeFeature{settings: sampleSettings()}
		body := strings.Replace(contractSettingsJSON, `"password": ""`, `"password": "newpass"`, 1)

		w := eaDo(eaEngine(f), http.MethodPut, "/settings", body)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		require.JSONEq(t, contractSettingsJSON, w.Body.String())

		want := sampleSettings()
		want.Password = "newpass"
		require.Equal(t, []dtov2.EASettings{want}, f.updated)
	})

	t.Run("POST test with an empty body tests the stored settings", func(t *testing.T) {
		t.Parallel()

		f := &eaFakeFeature{test: dtov2.EATestResult{
			ActiveDirectory:      dtov2.EACheck{OK: true, Message: "Bound to dc1.vprodemo.com as svc-ea@vprodemo.com (DC=vprodemo,DC=com)"},
			CertificateAuthority: dtov2.EACheck{Message: "adcs: connection refused"},
		}}

		w := eaDo(eaEngine(f), http.MethodPost, "/test", "")
		require.Equal(t, http.StatusOK, w.Code)
		require.JSONEq(t, `{
			"activeDirectory": {"ok": true, "message": "Bound to dc1.vprodemo.com as svc-ea@vprodemo.com (DC=vprodemo,DC=com)"},
			"certificateAuthority": {"ok": false, "message": "adcs: connection refused"}
		}`, w.Body.String())
		require.Equal(t, []*dtov2.EASettings{nil}, f.tested)
	})

	t.Run("POST test with a body tests it", func(t *testing.T) {
		t.Parallel()

		f := &eaFakeFeature{}
		w := eaDo(eaEngine(f), http.MethodPost, "/test", contractSettingsJSON)
		require.Equal(t, http.StatusOK, w.Code)
		require.Len(t, f.tested, 1)
		require.NotNil(t, f.tested[0])
		require.Equal(t, "vprodemo.com", f.tested[0].ActiveDirectory.Domain)
	})

	t.Run("lists", func(t *testing.T) {
		t.Parallel()

		f := &eaFakeFeature{
			list: []string{"CN=Computers", "OU=AMT,OU=Devices"},
			cas:  []dtov2.EAAuthority{{Name: "vprodemo-CA", Host: "ca1.vprodemo.com", Templates: []string{"AMT8021X", "WebServer"}}},
		}
		engine := eaEngine(f)

		for _, p := range []string{"/ad/containers", "/ad/groups"} {
			w := eaDo(engine, http.MethodGet, p, "")
			require.Equal(t, http.StatusOK, w.Code)
			require.JSONEq(t, `["CN=Computers","OU=AMT,OU=Devices"]`, w.Body.String())
		}

		w := eaDo(engine, http.MethodGet, "/ca/authorities", "")
		require.Equal(t, http.StatusOK, w.Code)
		require.JSONEq(t, `[{"name":"vprodemo-CA","host":"ca1.vprodemo.com","templates":["AMT8021X","WebServer"]}]`, w.Body.String())
	})
}

func TestEASettingsErrors(t *testing.T) {
	t.Parallel()

	notConfigured := eaKindErr{msg: "enterprise assistant: active directory is not configured", is: enterpriseassistant.ErrNotConfigured}
	validation := eaKindErr{msg: "enterprise assistant: deviceNameType must be hostname or nodeid", is: enterpriseassistant.ErrValidation}
	upstream := eaKindErr{msg: "enterprise assistant: upstream failure: active directory: boom", is: enterpriseassistant.ErrUpstream}
	internal := errors.New("config: write failed")

	routes := []struct{ method, path, body string }{
		{http.MethodPut, "/settings", contractSettingsJSON},
		{http.MethodPost, "/test", ""},
		{http.MethodGet, "/ad/containers", ""},
		{http.MethodGet, "/ad/groups", ""},
		{http.MethodGet, "/ca/authorities", ""},
	}

	errs := []struct {
		name string
		err  error
		code int
	}{
		{"validation", validation, http.StatusBadRequest},
		{"not configured", notConfigured, http.StatusBadRequest},
		{"upstream", upstream, http.StatusBadGateway},
		{"internal", internal, http.StatusInternalServerError},
	}

	for _, rt := range routes {
		for _, e := range errs {
			t.Run(rt.method+" "+rt.path+" "+e.name, func(t *testing.T) {
				t.Parallel()

				w := eaDo(eaEngine(&eaFakeFeature{err: e.err}), rt.method, rt.path, rt.body)
				require.Equal(t, e.code, w.Code)

				want, err := json.Marshal(map[string]string{"error": e.err.Error()})
				require.NoError(t, err)
				require.JSONEq(t, string(want), w.Body.String())
			})
		}
	}

	bodies := []struct {
		name, method, path, body string
		code                     int
	}{
		{"PUT malformed", http.MethodPut, "/settings", "{", http.StatusBadRequest},
		{"PUT empty", http.MethodPut, "/settings", "", http.StatusBadRequest},
		{"PUT wrong type", http.MethodPut, "/settings", `{"enabled":"yes"}`, http.StatusBadRequest},
		{"POST test malformed", http.MethodPost, "/test", "[", http.StatusBadRequest},
		{"PUT too large", http.MethodPut, "/settings", `{"url":"` + strings.Repeat("a", eaMaxBodyBytes) + `"}`, http.StatusRequestEntityTooLarge},
	}

	for _, b := range bodies {
		t.Run(b.name, func(t *testing.T) {
			t.Parallel()

			f := &eaFakeFeature{}
			w := eaDo(eaEngine(f), b.method, b.path, b.body)
			require.Equal(t, b.code, w.Code)

			var got map[string]string
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
			require.NotEmpty(t, got["error"])
			require.Empty(t, f.updated)
			require.Empty(t, f.tested)
		})
	}
}
