package ea

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	dto "github.com/device-management-toolkit/console/internal/entity/dto/v2"
	"github.com/device-management-toolkit/console/internal/usecase/enterpriseassistant"
	"github.com/device-management-toolkit/console/pkg/logger"
)

const testGUID = "4c4c4544-0046-3310-8051-b2c04f305032"

// rpcgoResponse and rpcgoProfile are copied verbatim (field names, types and
// tags) from rpc-go origin/main internal/certs/ea/ea.go (Response, Profile):
// this is the shape rpc-go marshals requests from and decodes answers into.
type rpcgoResponse struct {
	CSR           string `json:"csr"`
	KeyInstanceId string `json:"keyInstanceId"` //nolint:revive // copied from rpc-go
	AuthProtocol  int    `json:"authProtocol"`
	Certificate   string `json:"certificate"`
	Domain        string `json:"domain"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	RootCert      string `json:"rootcert"`
}

type rpcgoProfile struct {
	NodeID        string        `json:"nodeid"`
	Domain        string        `json:"domain"`
	ReqID         string        `json:"reqid"`
	AuthProtocol  int           `json:"authProtocol"`
	OSName        string        `json:"osname"`
	DevName       string        `json:"devname"`
	Icon          int           `json:"icon"`
	Ver           string        `json:"ver"`
	SignedCSR     string        `json:"signedcsr"`
	DERKey        string        `json:"DERKey"`
	KeyInstanceId string        `json:"keyInstanceId"` //nolint:revive // copied from rpc-go
	Response      rpcgoResponse `json:"response"`
}

// fakeFeature is a hand-written enterpriseassistant.Feature.
type fakeFeature struct {
	mu sync.Mutex

	access enterpriseassistant.DeviceAccess
	resp   dto.EADeviceResponse
	err    error
	remove dto.EARemoveResult

	calls []string
	reqs  []dto.EADeviceRequest
}

func (f *fakeFeature) record(name string, req dto.EADeviceRequest) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls = append(f.calls, name)
	f.reqs = append(f.reqs, req)
}

func (f *fakeFeature) DeviceAccess() enterpriseassistant.DeviceAccess {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.access
}

func (f *fakeFeature) Profile(_ context.Context, req dto.EADeviceRequest) (dto.EADeviceResponse, error) {
	f.record("profile", req)

	return f.resp, f.err
}

func (f *fakeFeature) KeyPair(_ context.Context, req dto.EADeviceRequest) (dto.EADeviceResponse, error) {
	f.record("keypair", req)

	return f.resp, f.err
}

func (f *fakeFeature) CSR(_ context.Context, req dto.EADeviceRequest) (dto.EADeviceResponse, error) {
	f.record("csr", req)

	return f.resp, f.err
}

func (f *fakeFeature) Remove(_ context.Context, req dto.EADeviceRequest) (dto.EARemoveResult, error) {
	f.record("remove", req)

	return f.remove, f.err
}

func (f *fakeFeature) GetSettings(context.Context) dto.EASettings { return dto.EASettings{} }

func (f *fakeFeature) UpdateSettings(context.Context, dto.EASettings) (dto.EASettings, error) {
	return dto.EASettings{}, nil
}

func (f *fakeFeature) TestSettings(context.Context, *dto.EASettings) (dto.EATestResult, error) {
	return dto.EATestResult{}, nil
}

func (f *fakeFeature) Containers(context.Context) ([]string, error)     { return nil, nil }
func (f *fakeFeature) SecurityGroups(context.Context) ([]string, error) { return nil, nil }

func (f *fakeFeature) Authorities(context.Context) ([]dto.EAAuthority, error) { return nil, nil }

var enabledAccess = enterpriseassistant.DeviceAccess{Enabled: true, Username: "eauser", Password: "eapass"}

func newTestRouter(t *testing.T, f *fakeFeature) (*gin.Engine, *Routes) {
	t.Helper()

	gin.SetMode(gin.TestMode)

	engine := gin.New()
	r := NewRoutes(engine.Group("/ea"), f, logger.New("error"))

	return engine, r
}

func do(engine *gin.Engine, method, path, token string, body any) *httptest.ResponseRecorder {
	var reader *bytes.Reader

	switch b := body.(type) {
	case nil:
		reader = bytes.NewReader(nil)
	case string:
		reader = bytes.NewReader([]byte(b))
	default:
		raw, _ := json.Marshal(b)
		reader = bytes.NewReader(raw)
	}

	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	return w
}

func login(t *testing.T, engine *gin.Engine, guid string) string {
	t.Helper()

	w := do(engine, http.MethodPost, "/ea/api/authenticate/"+guid, "", map[string]string{"username": "eauser", "password": "eapass"})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var got struct {
		Token string `json:"jwtToken"`
	}

	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	require.NotEmpty(t, got.Token)

	return got.Token
}

func requireStatus(t *testing.T, w *httptest.ResponseRecorder, code int, status string) {
	t.Helper()

	require.Equal(t, code, w.Code, w.Body.String())
	require.JSONEq(t, `{"status":"`+status+`"}`, w.Body.String())
}

func TestAuthenticate(t *testing.T) {
	t.Parallel()

	t.Run("success issues an HS256 token for the guid", func(t *testing.T) {
		t.Parallel()

		engine, r := newTestRouter(t, &fakeFeature{access: enabledAccess})
		token := login(t, engine, testGUID)

		claims := jwt.MapClaims{}
		parsed, err := jwt.ParseWithClaims(token, claims, func(*jwt.Token) (any, error) { return r.key, nil })
		require.NoError(t, err)
		require.Equal(t, "HS256", parsed.Method.Alg())
		require.Equal(t, testGUID, claims["deviceId"])

		exp, err := claims.GetExpirationTime()
		require.NoError(t, err)
		require.WithinDuration(t, time.Now().Add(60*time.Minute), exp.Time, 5*time.Second)
	})

	tests := []struct {
		name   string
		access enterpriseassistant.DeviceAccess
		body   any
	}{
		{"wrong username", enabledAccess, map[string]string{"username": "x", "password": "eapass"}},
		{"wrong password", enabledAccess, map[string]string{"username": "eauser", "password": "x"}},
		{"empty configured username", enterpriseassistant.DeviceAccess{Enabled: true, Password: "eapass"}, map[string]string{"username": "", "password": "eapass"}},
		{"empty configured password", enterpriseassistant.DeviceAccess{Enabled: true, Username: "eauser"}, map[string]string{"username": "eauser", "password": ""}},
		{"malformed body", enabledAccess, "{"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			engine, _ := newTestRouter(t, &fakeFeature{access: tt.access})
			w := do(engine, http.MethodPost, "/ea/api/authenticate/"+testGUID, "", tt.body)
			requireStatus(t, w, http.StatusUnauthorized, "Unauthorized")
		})
	}
}

func signed(t *testing.T, method jwt.SigningMethod, key any, claims jwt.MapClaims) string {
	t.Helper()

	s, err := jwt.NewWithClaims(method, claims).SignedString(key)
	require.NoError(t, err)

	return s
}

func TestTokenChecks(t *testing.T) {
	t.Parallel()

	exp := time.Now().Add(time.Hour).Unix()

	tests := []struct {
		name   string
		token  func(r *Routes) string
		header string
		status string
	}{
		{"no authorization header", func(*Routes) string { return "" }, "", "Unauthorized"},
		{"not a bearer header", func(*Routes) string { return "" }, "Basic abc", "Unauthorized"},
		{"garbage token", func(*Routes) string { return "not.a.jwt" }, "", "Invalid Token"},
		{"signed with another key", func(*Routes) string {
			return signed(t, jwt.SigningMethodHS256, []byte("another-key-another-key-another!"), jwt.MapClaims{"deviceId": testGUID, "exp": exp})
		}, "", "Invalid Token"},
		{"alg none", func(*Routes) string {
			return signed(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, jwt.MapClaims{"deviceId": testGUID, "exp": exp})
		}, "", "Invalid Token"},
		{"HS512 with the right key", func(r *Routes) string {
			return signed(t, jwt.SigningMethodHS512, r.key, jwt.MapClaims{"deviceId": testGUID, "exp": exp})
		}, "", "Invalid Token"},
		{"expired", func(r *Routes) string {
			return signed(t, jwt.SigningMethodHS256, r.key, jwt.MapClaims{"deviceId": testGUID, "exp": time.Now().Add(-time.Minute).Unix()})
		}, "", "Invalid Token"},
		{"no exp", func(r *Routes) string {
			return signed(t, jwt.SigningMethodHS256, r.key, jwt.MapClaims{"deviceId": testGUID})
		}, "", "Invalid Token"},
		{"no deviceId", func(r *Routes) string {
			return signed(t, jwt.SigningMethodHS256, r.key, jwt.MapClaims{"exp": exp})
		}, "", "Invalid Token"},
		{"guid mismatch", func(r *Routes) string {
			return signed(t, jwt.SigningMethodHS256, r.key, jwt.MapClaims{"deviceId": "11111111-2222-3333-4444-555555555555", "exp": exp})
		}, "", "GUID Mismatch"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := &fakeFeature{access: enabledAccess}
			engine, r := newTestRouter(t, f)

			req := httptest.NewRequest(http.MethodPost, "/ea/api/configure/profile/"+testGUID, strings.NewReader(`{"nodeid":"x"}`))
			if tok := tt.token(r); tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok)
			} else if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}

			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)

			requireStatus(t, w, http.StatusUnauthorized, tt.status)
			require.Empty(t, f.calls)
		})
	}

	t.Run("token from another guid's login", func(t *testing.T) {
		t.Parallel()

		f := &fakeFeature{access: enabledAccess}
		engine, _ := newTestRouter(t, f)
		token := login(t, engine, "11111111-2222-3333-4444-555555555555")

		w := do(engine, http.MethodPost, "/ea/api/configure/keypair/"+testGUID, token, rpcgoProfile{NodeID: testGUID})
		requireStatus(t, w, http.StatusUnauthorized, "GUID Mismatch")
	})
}

func TestDisabledAnswers404(t *testing.T) {
	t.Parallel()

	paths := []struct{ method, path string }{
		{http.MethodPost, "/ea/api/authenticate/" + testGUID},
		{http.MethodPost, "/ea/api/configure/profile/" + testGUID},
		{http.MethodPost, "/ea/api/configure/keypair/" + testGUID},
		{http.MethodPost, "/ea/api/configure/csr/" + testGUID},
		{http.MethodDelete, "/ea/api/configure/" + testGUID},
	}

	for _, p := range paths {
		t.Run(p.method+" "+p.path, func(t *testing.T) {
			t.Parallel()

			f := &fakeFeature{access: enterpriseassistant.DeviceAccess{Username: "eauser", Password: "eapass"}}
			engine, _ := newTestRouter(t, f)

			w := do(engine, p.method, p.path, "", map[string]string{"username": "eauser", "password": "eapass"})
			requireStatus(t, w, http.StatusNotFound, "Not a valid endpoint")
			require.Empty(t, f.calls)
		})
	}
}

func intPtr(v int) *int { return &v }

func TestConfigureRoutesSpeakRPCGo(t *testing.T) {
	t.Parallel()

	request := rpcgoProfile{
		NodeID: testGUID, OSName: "win11", DevName: "host1", Icon: 1,
		DERKey: "AQID", KeyInstanceId: "Intel(r) AMT Key: Handle: 0", SignedCSR: "BAUG",
	}
	echo := dto.EADeviceRequest{
		NodeID: testGUID, OSName: "win11", DevName: "host1", Icon: 1,
		DERKey: "AQID", KeyInstanceID: "Intel(r) AMT Key: Handle: 0", SignedCSR: "BAUG",
	}

	tests := []struct {
		name  string
		path  string
		call  string
		body  dto.EADeviceResponseBody
		check func(t *testing.T, got rpcgoProfile, raw map[string]any)
	}{
		{
			"profile asks for a key pair", "profile", "profile",
			dto.EADeviceResponseBody{},
			func(t *testing.T, _ rpcgoProfile, raw map[string]any) {
				t.Helper()
				require.Equal(t, "KeyPair-Request", raw["subaction"])
				require.Equal(t, map[string]any{}, raw["response"])
			},
		},
		{
			"keypair returns the csr", "keypair", "keypair",
			dto.EADeviceResponseBody{CSR: "MIIBCSR==", KeyInstanceID: "Intel(r) AMT Key: Handle: 0"},
			func(t *testing.T, got rpcgoProfile, raw map[string]any) {
				t.Helper()
				require.Equal(t, "MIIBCSR==", got.Response.CSR)
				require.Equal(t, "Intel(r) AMT Key: Handle: 0", got.Response.KeyInstanceId)
				require.Equal(t, map[string]any{"csr": "MIIBCSR==", "keyInstanceId": "Intel(r) AMT Key: Handle: 0"}, raw["response"])
			},
		},
		{"csr returns the certificate", "csr", "csr", dto.EADeviceResponseBody{
			AuthProtocol: intPtr(0), Certificate: "MIICERT==", RootCert: "MIIROOT==", Domain: "vprodemo.com", Username: "iME$host1$",
		}, func(t *testing.T, got rpcgoProfile, raw map[string]any) {
			t.Helper()
			require.Equal(t, "MIICERT==", got.Response.Certificate)
			require.Equal(t, "MIIROOT==", got.Response.RootCert)
			require.Equal(t, map[string]any{
				"authProtocol": float64(0), "certificate": "MIICERT==", "rootcert": "MIIROOT==", "domain": "vprodemo.com", "username": "iME$host1$",
			}, raw["response"])
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := &fakeFeature{access: enabledAccess, resp: dto.EADeviceResponse{
				EADeviceRequest: echo, Action: "satellite", SatelliteFlags: 2, SubAction: "x", Response: tt.body,
			}}
			if tt.call == "profile" {
				f.resp.SubAction = "KeyPair-Request"
			}

			engine, _ := newTestRouter(t, f)
			token := login(t, engine, testGUID)

			w := do(engine, http.MethodPost, "/ea/api/configure/"+tt.path+"/"+testGUID, token, request)
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())

			require.Equal(t, []string{tt.call}, f.calls)
			require.Equal(t, echo, f.reqs[0], "rpc-go's JSON decodes into the request DTO")

			var got rpcgoProfile
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
			require.Equal(t, testGUID, got.NodeID)

			var raw map[string]any
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))
			require.Equal(t, "satellite", raw["action"])
			require.InDelta(t, 2, raw["satelliteFlags"], 0)

			tt.check(t, got, raw)
		})
	}
}

func TestConfigureErrors(t *testing.T) {
	t.Parallel()

	validation := enterpriseassistant.ErrValidation
	upstream := enterpriseassistant.ErrUpstream

	tests := []struct {
		name    string
		err     error
		body    any
		code    int
		details string
	}{
		{"validation", fakeErr{msg: "Validation failed: Nodeid is required.", is: validation}, rpcgoProfile{}, http.StatusBadRequest, "Validation failed: Nodeid is required."},
		{"upstream", fakeErr{msg: "enterprise assistant: upstream failure: active directory: boom", is: upstream}, rpcgoProfile{NodeID: testGUID}, http.StatusBadGateway, "enterprise assistant: upstream failure: active directory: boom"},
		{"not configured", fakeErr{msg: "enterprise assistant: certificate authority is not configured", is: enterpriseassistant.ErrNotConfigured}, rpcgoProfile{NodeID: testGUID}, http.StatusInternalServerError, "enterprise assistant: certificate authority is not configured"},
		{"malformed json", nil, "{", http.StatusBadRequest, "Validation failed: request body is not valid JSON."},
		{"empty body", nil, nil, http.StatusBadRequest, "Validation failed: request body is not valid JSON."},
		{"body too large", nil, `{"nodeid":"` + strings.Repeat("a", MaxBodyBytes) + `"}`, http.StatusRequestEntityTooLarge, "Request body too large"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := &fakeFeature{access: enabledAccess, err: tt.err}
			engine, _ := newTestRouter(t, f)
			token := login(t, engine, testGUID)

			w := do(engine, http.MethodPost, "/ea/api/configure/profile/"+testGUID, token, tt.body)
			require.Equal(t, tt.code, w.Code, w.Body.String())

			var got rpcgoProfile
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got), "rpc-go must still decode an error body")

			body, err := json.Marshal(map[string]string{"status": "Error", "details": tt.details})
			require.NoError(t, err)
			require.JSONEq(t, string(body), w.Body.String())
		})
	}
}

type fakeErr struct {
	msg string
	is  error
}

func (e fakeErr) Error() string        { return e.msg }
func (e fakeErr) Is(target error) bool { return target == e.is }

func TestRemove(t *testing.T) {
	t.Parallel()

	t.Run("empty body uses the guid as nodeid", func(t *testing.T) {
		t.Parallel()

		f := &fakeFeature{access: enabledAccess, remove: dto.EARemoveResult{Status: "Success", Removed: true}}
		engine, _ := newTestRouter(t, f)
		token := login(t, engine, testGUID)

		w := do(engine, http.MethodDelete, "/ea/api/configure/"+testGUID, token, nil)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		require.JSONEq(t, `{"status":"Success","removed":true}`, w.Body.String())
		require.Equal(t, testGUID, f.reqs[0].NodeID)
	})

	t.Run("body is passed through", func(t *testing.T) {
		t.Parallel()

		f := &fakeFeature{access: enabledAccess}
		engine, _ := newTestRouter(t, f)
		token := login(t, engine, testGUID)

		w := do(engine, http.MethodDelete, "/ea/api/configure/"+testGUID, token, rpcgoProfile{NodeID: "other", DevName: "host1"})
		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, "host1", f.reqs[0].DevName)
		require.Equal(t, "other", f.reqs[0].NodeID)
	})

	t.Run("requires a token", func(t *testing.T) {
		t.Parallel()

		engine, _ := newTestRouter(t, &fakeFeature{access: enabledAccess})
		w := do(engine, http.MethodDelete, "/ea/api/configure/"+testGUID, "", nil)
		requireStatus(t, w, http.StatusUnauthorized, "Unauthorized")
	})

	t.Run("upstream failure", func(t *testing.T) {
		t.Parallel()

		f := &fakeFeature{access: enabledAccess, err: fakeErr{msg: "x", is: enterpriseassistant.ErrUpstream}}
		engine, _ := newTestRouter(t, f)
		token := login(t, engine, testGUID)

		w := do(engine, http.MethodDelete, "/ea/api/configure/"+testGUID, token, nil)
		require.Equal(t, http.StatusBadGateway, w.Code)
	})
}

func TestEnabledIsCheckedPerRequest(t *testing.T) {
	t.Parallel()

	f := &fakeFeature{access: enabledAccess}
	engine, _ := newTestRouter(t, f)
	_ = login(t, engine, testGUID)

	f.mu.Lock()
	f.access.Enabled = false
	f.mu.Unlock()

	w := do(engine, http.MethodPost, "/ea/api/authenticate/"+testGUID, "", map[string]string{"username": "eauser", "password": "eapass"})
	requireStatus(t, w, http.StatusNotFound, "Not a valid endpoint")
}
