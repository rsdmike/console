package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/device-management-toolkit/console/config"
	"github.com/device-management-toolkit/console/internal/usecase"
	"github.com/device-management-toolkit/console/internal/usecase/enterpriseassistant"
	"github.com/device-management-toolkit/console/pkg/logger"
)

const (
	routerTestJWTKey = "router-test-api-jwt-key-0123456789"
	routerTestGUID   = "4c4c4544-0046-3310-8051-b2c04f305032"
)

var (
	routerCfgOnce sync.Once
	routerCfg     *config.Config
)

// routerTestConfig installs one process-wide config: the API middleware and
// the EA use case read config.ConsoleConfig.
func routerTestConfig() *config.Config {
	routerCfgOnce.Do(func() {
		cfg := &config.Config{}
		cfg.JWTKey = routerTestJWTKey
		cfg.JWTExpiration = time.Hour
		cfg.EA = config.EA{
			Enabled: true, Username: "eauser", Password: "eapass", DeviceNameType: "hostname",
			CA: config.EACertificateAuthority{CommonName: "dnsfqdn"},
		}
		config.ConsoleConfig = cfg
		routerCfg = cfg
	})

	return routerCfg
}

var (
	routerOnce   sync.Once
	routerEngine *gin.Engine
)

// newRouterUnderTest builds the router once: NewRouter registers global
// validators and Prometheus collectors, so concurrent builds race.
func newRouterUnderTest(t *testing.T) *gin.Engine {
	t.Helper()

	routerOnce.Do(func() {
		gin.SetMode(gin.TestMode)

		cfg := routerTestConfig()
		l := logger.New("error")

		// The settings GET needs no AD, so nil factories are fine here.
		uc := usecase.Usecases{EnterpriseAssistant: enterpriseassistant.New(l, nil, nil, nil, nil)}

		routerEngine = gin.New()
		NewRouter(routerEngine, l, uc, cfg)
	})

	return routerEngine
}

func serve(engine *gin.Engine, method, path, token string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}

	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	return w
}

func apiToken(t *testing.T) string {
	t.Helper()

	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(routerTestJWTKey))
	require.NoError(t, err)

	return tok
}

func eaToken(t *testing.T, engine *gin.Engine) string {
	t.Helper()

	w := serve(engine, http.MethodPost, "/ea/api/authenticate/"+routerTestGUID, "", map[string]string{"username": "eauser", "password": "eapass"})
	require.Equal(t, http.StatusOK, w.Code, "the EA login is reachable without an API token: %s", w.Body.String())

	var got struct {
		Token string `json:"jwtToken"`
	}

	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))

	return got.Token
}

func TestRouterEnterpriseAssistantMounting(t *testing.T) {
	t.Parallel()

	const settings = "/api/v2/admin/enterprise-assistant/settings"

	t.Run("settings API is behind the API JWT middleware", func(t *testing.T) {
		t.Parallel()

		engine := newRouterUnderTest(t)

		w := serve(engine, http.MethodGet, settings, "", nil)
		require.Equal(t, http.StatusUnauthorized, w.Code)
		require.Contains(t, w.Body.String(), "access token")

		w = serve(engine, http.MethodGet, settings, apiToken(t), nil)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		require.Contains(t, w.Body.String(), `"passwordSet":true`)
		require.NotContains(t, w.Body.String(), "eapass")
	})

	t.Run("/ea is outside the API JWT group", func(t *testing.T) {
		t.Parallel()

		engine := newRouterUnderTest(t)
		require.NotEmpty(t, eaToken(t, engine))
	})

	t.Run("an EA token does not pass the API middleware", func(t *testing.T) {
		t.Parallel()

		engine := newRouterUnderTest(t)

		w := serve(engine, http.MethodGet, settings, eaToken(t, engine), nil)
		require.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("an API token does not pass the EA middleware", func(t *testing.T) {
		t.Parallel()

		engine := newRouterUnderTest(t)

		w := serve(engine, http.MethodPost, "/ea/api/configure/profile/"+routerTestGUID, apiToken(t), map[string]string{"nodeid": routerTestGUID})
		require.Equal(t, http.StatusUnauthorized, w.Code)
		require.JSONEq(t, `{"status":"Invalid Token"}`, w.Body.String())
	})
}
