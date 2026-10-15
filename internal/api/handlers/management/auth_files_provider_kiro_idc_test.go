package management

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	sdkauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func newKiroRequestHandler(t *testing.T, cfg *config.Config) *Handler {
	t.Helper()
	dir := t.TempDir()
	store := sdkauth.NewFileTokenStore()
	store.SetBaseDir(dir)
	if cfg == nil {
		cfg = &config.Config{}
	}
	cfg.AuthDir = dir
	return &Handler{cfg: cfg, authManager: coreauth.NewManager(nil, nil, nil), tokenStore: store}
}

func callRequestKiroToken(t *testing.T, handler *Handler, query string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/kiro-auth-url?"+query, nil)
	handler.RequestKiroToken(ctx)
	return recorder
}

func TestRequestKiroTokenRejectsIdentityCenterWithoutStartURL(t *testing.T) {
	handler := newKiroRequestHandler(t, nil)
	recorder := callRequestKiroToken(t, handler, "provider=organization")

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "startUrl") {
		t.Fatalf("error should name the missing parameter: %s", recorder.Body.String())
	}
}

func TestRequestKiroTokenStartsIdentityCenterDeviceFlow(t *testing.T) {
	var deviceBody map[string]any
	oidc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/client/register":
			_, _ = io.WriteString(w, `{"clientId":"cid","clientSecret":"csec"}`)
		case "/device_authorization":
			if err := json.NewDecoder(r.Body).Decode(&deviceBody); err != nil {
				t.Errorf("decode device authorization: %v", err)
			}
			_, _ = io.WriteString(w, `{
				"deviceCode":"dev",
				"userCode":"WXYZ-9999",
				"verificationUri":"https://device.sso.us-east-1.amazonaws.com/",
				"verificationUriComplete":"https://view.awsapps.com/start/#/device?user_code=WXYZ-9999",
				"expiresIn":600,
				"interval":1
			}`)
		case "/token":
			// Fail the poll immediately so the background goroutine does not linger.
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"expired_token"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(oidc.Close)

	handler := newKiroRequestHandler(t, &config.Config{
		OAuthEndpointOverrides: map[string]config.OAuthEndpointConfig{
			"kiro": {ApiBaseURL: oidc.URL},
		},
	})
	recorder := callRequestKiroToken(t, handler, "provider=organization&startUrl=https://acme.awsapps.com/start&region=us-east-1")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Status   string `json:"status"`
		URL      string `json:"url"`
		State    string `json:"state"`
		Flow     string `json:"flow"`
		UserCode string `json:"user_code"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Status != "ok" || payload.Flow != "device" || payload.State == "" {
		t.Fatalf("response = %+v", payload)
	}
	// The portal device page must win over the Builder ID page AWS returns.
	if payload.URL != "https://acme.awsapps.com/start/#/device?user_code=WXYZ-9999" {
		t.Fatalf("auth url = %q", payload.URL)
	}
	if payload.UserCode != "WXYZ-9999" {
		t.Fatalf("user code = %q", payload.UserCode)
	}
	if deviceBody["startUrl"] != "https://acme.awsapps.com/start" {
		t.Fatalf("device authorization body = %#v", deviceBody)
	}
}

func TestRequestKiroTokenRejectsValueThatIsNotAnAPIKey(t *testing.T) {
	handler := newKiroRequestHandler(t, nil)
	recorder := callRequestKiroToken(t, handler, "provider=apikey&apiKey=not-a-key")

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "ksk_") {
		t.Fatalf("error should explain the expected key format: %s", recorder.Body.String())
	}
}
