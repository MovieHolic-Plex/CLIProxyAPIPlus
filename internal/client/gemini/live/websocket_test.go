package live

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestDialUsesGeminiHostPathAndCredential(t *testing.T) {
	requests := make(chan *http.Request, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Clone(r.Context())
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		_ = conn.Close()
	}))
	defer upstream.Close()
	selected := &auth.Auth{ProxyURL: "direct", Attributes: map[string]string{
		auth.AttributeAPIKey:   "upstream-secret-key",
		"base_url":             upstream.URL + "/v1beta?key=obsolete",
		"header:X-Custom":      "configured",
		"header:Authorization": "Bearer obsolete",
	}}
	cfg := &config.Config{}
	cfg.ProxyURL = "invalid://ignored-by-credential"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, status, err := dial(ctx, cfg, selected)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if status != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d", status)
	}
	request := <-requests
	if request.URL.Path != Path || request.URL.Query().Get("key") != "upstream-secret-key" {
		t.Fatalf("upstream request = %s", request.URL)
	}
	if request.Header.Get("Authorization") != "" || request.Header.Get("x-goog-api-key") != "upstream-secret-key" {
		t.Fatalf("wrong credential headers: %#v", request.Header)
	}
	if request.Header.Get("X-Custom") != "configured" {
		t.Fatalf("custom header = %q", request.Header.Get("X-Custom"))
	}
}

func TestDialUsesGlobalProxy(t *testing.T) {
	requests := make(chan *http.Request, 1)
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Clone(r.Context())
		w.WriteHeader(http.StatusForbidden)
	}))
	defer proxyServer.Close()
	cfg := &config.Config{}
	cfg.ProxyURL = proxyServer.URL
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := dial(ctx, cfg, &auth.Auth{Attributes: map[string]string{
		auth.AttributeAPIKey: "upstream-key",
		"base_url":           "https://gemini.invalid",
	}})
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("expected rejected proxy CONNECT")
	}
	select {
	case request := <-requests:
		if request.Method != http.MethodConnect || request.Host != "gemini.invalid:443" {
			t.Fatalf("proxy request = %s %s", request.Method, request.Host)
		}
	case <-ctx.Done():
		t.Fatal("proxy was not used")
	}
}

func TestLiveRejectsPayloadModelRewrite(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{Payload: config.PayloadConfig{Override: []config.PayloadRule{{
		Models: []config.PayloadModelRule{{Name: "*", Protocol: "gemini"}},
		Params: map[string]any{"model": "models/other-model"},
	}}}}
	handler := NewHandler(auth.NewManager(nil, nil, nil), func() *config.Config { return cfg })
	router := gin.New()
	router.GET(Path, func(c *gin.Context) {
		c.Set("userApiKey", "test-key")
		handler.Handle(c)
	})
	server := httptest.NewServer(router)
	defer server.Close()
	conn, response, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+Path, nil)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"setup":{"model":"models/gemini-3.5-transcribe-live"}}`)); err != nil {
		t.Fatal(err)
	}
	_, _, err = conn.ReadMessage()
	if !websocket.IsCloseError(err, websocket.ClosePolicyViolation) {
		t.Fatalf("close = %v, want 1008", err)
	}
}

func TestCloseDetailsNeverSendsReservedCodes(t *testing.T) {
	for _, code := range []int{1005, 1006, 1015} {
		got, _ := closeDetails(&websocket.CloseError{Code: code})
		if got != websocket.CloseInternalServerErr {
			t.Errorf("closeDetails(%d) = %d", code, got)
		}
	}
	code, reason := closeDetails(&websocket.CloseError{Code: 1008, Text: "policy"})
	if code != 1008 || reason != "policy" {
		t.Fatalf("closeDetails() = %d %q", code, reason)
	}
}
