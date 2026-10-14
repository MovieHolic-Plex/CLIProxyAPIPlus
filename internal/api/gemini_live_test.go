package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

const (
	geminiLiveTestPath      = "/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent"
	geminiLiveTestModel     = "gemini-3.5-transcribe-live"
	geminiLiveTestClientKey = "gemini-live-client-key"
	geminiLiveTestTimeout   = 5 * time.Second
)

type geminiLiveTestFrame struct {
	kind int
	data []byte
}

func newGeminiLiveTestServer(t *testing.T, cfg *config.Config, upstreamURL string, credentials int, models ...string) (string, <-chan struct{}) {
	t.Helper()
	cfg.APIKeys = []string{geminiLiveTestClientKey}
	completed := make(chan struct{}, 16)
	server := newTestServerWithConfig(t, cfg, WithMiddleware(func(c *gin.Context) {
		c.Next()
		completed <- struct{}{}
	}))
	manager := server.handlers.AuthManager
	manager.SetConfig(cfg)
	manager.SetSelector(&coreauth.FillFirstSelector{})
	manager.RegisterExecutor(executor.NewGeminiExecutor(cfg))
	for i := 0; i < credentials; i++ {
		id := fmt.Sprintf("%s-credential-%d", t.Name(), i)
		record := &coreauth.Auth{
			ID:       id,
			Provider: "gemini",
			Status:   coreauth.StatusActive,
			Attributes: map[string]string{
				"api_key":  fmt.Sprintf("upstream-key-%d", i),
				"base_url": upstreamURL,
				"priority": fmt.Sprint(credentials - i),
			},
			Metadata: map[string]any{"disable_cooling": cfg.DisableCooling},
		}
		if _, err := manager.Register(context.Background(), record); err != nil {
			t.Fatalf("register Gemini credential: %v", err)
		}
		infos := make([]*registry.ModelInfo, 0, len(models))
		for _, model := range models {
			infos = append(infos, &registry.ModelInfo{ID: model, Type: "gemini", OwnedBy: "google"})
		}
		registry.GetGlobalRegistry().RegisterClient(id, "gemini", infos)
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	}
	t.Cleanup(func() { coreauth.SetQuotaCooldownDisabled(false) })
	proxy := httptest.NewServer(server.engine)
	t.Cleanup(proxy.Close)
	return "ws" + strings.TrimPrefix(proxy.URL, "http"), completed
}

func geminiLiveTestUpgrade(t *testing.T, w http.ResponseWriter, r *http.Request) *websocket.Conn {
	t.Helper()
	upgrader := websocket.Upgrader{}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		t.Errorf("upgrade upstream: %v", err)
		return nil
	}
	if err := conn.SetReadDeadline(time.Now().Add(geminiLiveTestTimeout)); err != nil {
		t.Errorf("set upstream safety deadline: %v", err)
		_ = conn.Close()
		return nil
	}
	return conn
}

func geminiLiveTestDial(t *testing.T, url string, header http.Header) *websocket.Conn {
	t.Helper()
	dialer := websocket.Dialer{HandshakeTimeout: geminiLiveTestTimeout}
	conn, response, err := dialer.Dial(url, header)
	if err != nil {
		if response != nil {
			defer response.Body.Close()
			body, _ := io.ReadAll(response.Body)
			t.Fatalf("dial Gemini Live: %v; status=%d body=%s", err, response.StatusCode, body)
		}
		t.Fatalf("dial Gemini Live: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetReadDeadline(time.Now().Add(geminiLiveTestTimeout)); err != nil {
		t.Fatalf("set client safety deadline: %v", err)
	}
	return conn
}

func geminiLiveTestWrite(t *testing.T, conn *websocket.Conn, frame geminiLiveTestFrame) {
	t.Helper()
	if err := conn.WriteMessage(frame.kind, frame.data); err != nil {
		t.Fatalf("write client frame: %v", err)
	}
}

func geminiLiveTestRead(t *testing.T, conn *websocket.Conn, want geminiLiveTestFrame) {
	t.Helper()
	kind, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read client frame: %v", err)
	}
	if kind != want.kind || !bytes.Equal(data, want.data) {
		t.Fatalf("client frame = (%d, %q), want (%d, %q)", kind, data, want.kind, want.data)
	}
}

func geminiLiveTestAwait[T any](t *testing.T, event <-chan T) T {
	t.Helper()
	timer := time.NewTimer(geminiLiveTestTimeout)
	defer timer.Stop()
	select {
	case value := <-event:
		return value
	case <-timer.C:
		t.Fatal("timed out waiting for Gemini Live test event")
		var zero T
		return zero
	}
}

func geminiLiveTestClose(t *testing.T, err error, code int, reason string) {
	t.Helper()
	var closeErr *websocket.CloseError
	if !errors.As(err, &closeErr) {
		t.Fatalf("read error = %v, want WebSocket close %d %q", err, code, reason)
	}
	if closeErr.Code != code || closeErr.Text != reason {
		t.Fatalf("close = (%d, %q), want (%d, %q)", closeErr.Code, closeErr.Text, code, reason)
	}
}

func TestGeminiLiveClientAuthentication(t *testing.T) {
	for _, path := range []string{geminiLiveTestPath, "/v1beta" + geminiLiveTestPath} {
		for _, tc := range []struct {
			name   string
			header http.Header
			query  string
			valid  bool
		}{
			{name: "bearer", header: http.Header{"Authorization": {"Bearer " + geminiLiveTestClientKey}}, valid: true},
			{name: "google-header", header: http.Header{"X-Goog-Api-Key": {geminiLiveTestClientKey}}, valid: true},
			{name: "query", query: "?key=" + geminiLiveTestClientKey, valid: true},
			{name: "absent"},
			{name: "invalid-bearer", header: http.Header{"Authorization": {"Bearer invalid-client-key"}}},
			{name: "invalid-google-header", header: http.Header{"X-Goog-Api-Key": {"invalid-client-key"}}},
			{name: "invalid-query", query: "?key=invalid-client-key"},
		} {
			t.Run(path+"/"+tc.name, func(t *testing.T) {
				var upstreamCalls atomic.Int32
				setup := []byte(`{ "setup": { "model": "models/` + geminiLiveTestModel + `", "generationConfig": {"responseModalities":["TEXT"]}, "futureField": {"keep":true} } }`)
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					upstreamCalls.Add(1)
					if r.URL.Path != geminiLiveTestPath {
						t.Errorf("upstream path = %q, want %q", r.URL.Path, geminiLiveTestPath)
					}
					if got := r.URL.Query().Get("key"); got != "upstream-key-0" {
						t.Errorf("upstream key = %q, want selected credential key", got)
					}
					if strings.Contains(r.URL.RawQuery, geminiLiveTestClientKey) || strings.Contains(r.Header.Get("Authorization"), geminiLiveTestClientKey) || r.Header.Get("X-Goog-Api-Key") == geminiLiveTestClientKey {
						t.Error("client API key leaked to upstream")
					}
					conn := geminiLiveTestUpgrade(t, w, r)
					if conn == nil {
						return
					}
					defer conn.Close()
					kind, received, err := conn.ReadMessage()
					if err != nil || kind != websocket.TextMessage || !bytes.Equal(received, setup) {
						t.Errorf("upstream setup = (%d, %q, %v), want original setup bytes", kind, received, err)
						return
					}
					if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"setupComplete":{}}`)); err != nil {
						t.Errorf("write setupComplete: %v", err)
					}
				}))
				defer upstream.Close()
				url, completed := newGeminiLiveTestServer(t, &config.Config{}, upstream.URL, 1, geminiLiveTestModel)
				if tc.valid {
					conn := geminiLiveTestDial(t, url+path+tc.query, tc.header)
					geminiLiveTestWrite(t, conn, geminiLiveTestFrame{websocket.TextMessage, setup})
					geminiLiveTestRead(t, conn, geminiLiveTestFrame{websocket.TextMessage, []byte(`{"setupComplete":{}}`)})
					_ = conn.Close()
				} else {
					dialer := websocket.Dialer{HandshakeTimeout: geminiLiveTestTimeout}
					conn, response, err := dialer.Dial(url+path+tc.query, tc.header)
					if conn != nil {
						_ = conn.Close()
					}
					if response != nil {
						defer response.Body.Close()
					}
					if err == nil || response == nil || response.StatusCode != http.StatusUnauthorized {
						t.Fatalf("unauthorized handshake = (%v, %v), want HTTP 401", response, err)
					}
				}
				geminiLiveTestAwait(t, completed)
				wantCalls := int32(0)
				if tc.valid {
					wantCalls = 1
				}
				if got := upstreamCalls.Load(); got != wantCalls {
					t.Fatalf("upstream calls = %d, want %d", got, wantCalls)
				}
			})
		}
	}
}

func TestGeminiLiveBidirectionalFramesPreserveGenericModel(t *testing.T) {
	const model = "gemini-2.5-flash-native-audio-preview"
	setup := []byte(`{"setup":{"model":"models/` + model + `","generationConfig":{"responseModalities":["AUDIO"]}}}`)
	clientFrames := []geminiLiveTestFrame{
		{websocket.TextMessage, []byte(`{"realtimeInput":{"text":"hello"}}`)},
		{websocket.BinaryMessage, []byte{0, 1, 2, 255}},
		{websocket.TextMessage, []byte(`{"clientContent":{"turnComplete":true}}`)},
		{websocket.BinaryMessage, []byte{9, 0, 8, 0}},
	}
	serverFrames := []geminiLiveTestFrame{
		{websocket.TextMessage, []byte(`{"serverContent":{"modelTurn":{"parts":[{"text":"hello"}]}}}`)},
		{websocket.BinaryMessage, []byte{255, 2, 1, 0}},
		{websocket.TextMessage, []byte(`{"serverContent":{"turnComplete":true}}`)},
		{websocket.BinaryMessage, []byte{0, 8, 0, 9}},
	}
	upstreamClose := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn := geminiLiveTestUpgrade(t, w, r)
		if conn == nil {
			return
		}
		defer conn.Close()
		kind, received, err := conn.ReadMessage()
		if err != nil || kind != websocket.BinaryMessage || !bytes.Equal(received, setup) {
			t.Errorf("generic binary setup = (%d, %q, %v), want exact unrewritten setup", kind, received, err)
			return
		}
		if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"setupComplete":{}}`)); err != nil {
			t.Errorf("write setupComplete: %v", err)
			return
		}
		for i, want := range clientFrames {
			kind, received, err := conn.ReadMessage()
			if err != nil || kind != want.kind || !bytes.Equal(received, want.data) {
				t.Errorf("upstream frame %d = (%d, %q, %v), want (%d, %q)", i, kind, received, err, want.kind, want.data)
				return
			}
			frame := serverFrames[i]
			if err := conn.WriteMessage(frame.kind, frame.data); err != nil {
				t.Errorf("write upstream frame %d: %v", i, err)
				return
			}
		}
		_, _, err = conn.ReadMessage()
		upstreamClose <- err
	}))
	defer upstream.Close()
	url, completed := newGeminiLiveTestServer(t, &config.Config{}, upstream.URL, 1, model)
	conn := geminiLiveTestDial(t, url+geminiLiveTestPath+"?key="+geminiLiveTestClientKey, nil)
	geminiLiveTestWrite(t, conn, geminiLiveTestFrame{websocket.BinaryMessage, setup})
	geminiLiveTestRead(t, conn, geminiLiveTestFrame{websocket.TextMessage, []byte(`{"setupComplete":{}}`)})
	for i, frame := range clientFrames {
		geminiLiveTestWrite(t, conn, frame)
		geminiLiveTestRead(t, conn, serverFrames[i])
	}
	geminiLiveTestWrite(t, conn, geminiLiveTestFrame{websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "client finished")})
	geminiLiveTestClose(t, geminiLiveTestAwait(t, upstreamClose), websocket.CloseNormalClosure, "client finished")
	geminiLiveTestAwait(t, completed)
}

func TestGeminiLiveRetriesBeforeSetupComplete(t *testing.T) {
	for _, disabledCooling := range []bool{false, true} {
		for _, failure := range []int{websocket.CloseInternalServerErr, websocket.CloseTryAgainLater, websocket.ClosePolicyViolation, http.StatusServiceUnavailable} {
			t.Run(fmt.Sprintf("failure-%d/disable-cooling-%t", failure, disabledCooling), func(t *testing.T) {
				setup := []byte(`{ "setup": {"model":"models/` + geminiLiveTestModel + `","inputAudioTranscription":{}} }`)
				attempts := make(chan string, 8)
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					key := r.URL.Query().Get("key")
					attempts <- key
					if key == "upstream-key-0" && failure == http.StatusServiceUnavailable {
						http.Error(w, "credential unavailable", http.StatusServiceUnavailable)
						return
					}
					conn := geminiLiveTestUpgrade(t, w, r)
					if conn == nil {
						return
					}
					defer conn.Close()
					kind, data, err := conn.ReadMessage()
					if err != nil || kind != websocket.TextMessage || !bytes.Equal(data, setup) {
						t.Errorf("retry setup = (%d, %q, %v), want same setup bytes", kind, data, err)
						return
					}
					if key == "upstream-key-0" {
						if err := conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(failure, "first credential rejected")); err != nil {
							t.Errorf("write pre-setup close: %v", err)
						}
						return
					}
					if key != "upstream-key-1" {
						t.Errorf("retry credential key = %q", key)
						return
					}
					if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"setupComplete":{}}`)); err != nil {
						t.Errorf("write setupComplete: %v", err)
						return
					}
					if err := conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "second credential finished")); err != nil {
						t.Errorf("write final close: %v", err)
					}
				}))
				defer upstream.Close()
				cfg := &config.Config{DisableCooling: disabledCooling}
				url, completed := newGeminiLiveTestServer(t, cfg, upstream.URL, 2, geminiLiveTestModel)
				conn := geminiLiveTestDial(t, url+geminiLiveTestPath+"?key="+geminiLiveTestClientKey, nil)
				geminiLiveTestWrite(t, conn, geminiLiveTestFrame{websocket.TextMessage, setup})
				geminiLiveTestRead(t, conn, geminiLiveTestFrame{websocket.TextMessage, []byte(`{"setupComplete":{}}`)})
				_, _, err := conn.ReadMessage()
				geminiLiveTestClose(t, err, websocket.CloseNormalClosure, "second credential finished")
				geminiLiveTestAwait(t, completed)
				for _, want := range []string{"upstream-key-0", "upstream-key-1"} {
					if got := geminiLiveTestAwait(t, attempts); got != want {
						t.Fatalf("attempt credential = %q, want %q", got, want)
					}
				}
				select {
				case extra := <-attempts:
					t.Fatalf("unexpected extra credential attempt: %q", extra)
				default:
				}
			})
		}
	}
}

func TestGeminiLiveDoesNotRetryAfterSetupComplete(t *testing.T) {
	for _, code := range []int{websocket.CloseInternalServerErr, websocket.CloseTryAgainLater, websocket.ClosePolicyViolation} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			var attempts atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts.Add(1)
				conn := geminiLiveTestUpgrade(t, w, r)
				if conn == nil {
					return
				}
				defer conn.Close()
				if _, _, err := conn.ReadMessage(); err != nil {
					t.Errorf("read setup: %v", err)
					return
				}
				if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"setupComplete":{}}`)); err != nil {
					t.Errorf("write setupComplete: %v", err)
					return
				}
				if err := conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(code, "session terminated")); err != nil {
					t.Errorf("write upstream close: %v", err)
				}
			}))
			defer upstream.Close()
			url, completed := newGeminiLiveTestServer(t, &config.Config{}, upstream.URL, 2, geminiLiveTestModel)
			conn := geminiLiveTestDial(t, url+geminiLiveTestPath+"?key="+geminiLiveTestClientKey, nil)
			geminiLiveTestWrite(t, conn, geminiLiveTestFrame{websocket.TextMessage, []byte(`{"setup":{"model":"models/` + geminiLiveTestModel + `"}}`)})
			geminiLiveTestRead(t, conn, geminiLiveTestFrame{websocket.TextMessage, []byte(`{"setupComplete":{}}`)})
			_, _, err := conn.ReadMessage()
			geminiLiveTestClose(t, err, code, "session terminated")
			geminiLiveTestAwait(t, completed)
			if got := attempts.Load(); got != 1 {
				t.Fatalf("upstream attempts after setupComplete = %d, want 1", got)
			}
		})
	}
}

func TestGeminiLiveModelWhitelistDenial(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		http.Error(w, "whitelist must reject before upstream dial", http.StatusInternalServerError)
	}))
	defer upstream.Close()
	cfg := &config.Config{}
	cfg.APIKeyModelWhitelists = map[string][]string{geminiLiveTestClientKey: {"gemini-2.5-*"}}
	url, completed := newGeminiLiveTestServer(t, cfg, upstream.URL, 1, geminiLiveTestModel)
	conn := geminiLiveTestDial(t, url+geminiLiveTestPath+"?key="+geminiLiveTestClientKey, nil)
	geminiLiveTestWrite(t, conn, geminiLiveTestFrame{websocket.TextMessage, []byte(`{"setup":{"model":"models/` + geminiLiveTestModel + `"}}`)})
	_, _, err := conn.ReadMessage()
	geminiLiveTestClose(t, err, websocket.ClosePolicyViolation, "model is not allowed for this API key")
	geminiLiveTestAwait(t, completed)
	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("upstream calls for disallowed model = %d, want 0", got)
	}
}

func TestGeminiLiveHomeModeUnavailable(t *testing.T) {
	cfg := &config.Config{Home: config.HomeConfig{Enabled: true}}
	url, completed := newGeminiLiveTestServer(t, cfg, "", 0)
	dialer := websocket.Dialer{HandshakeTimeout: geminiLiveTestTimeout}
	conn, response, err := dialer.Dial(url+geminiLiveTestPath+"?key="+geminiLiveTestClientKey, nil)
	if conn != nil {
		_ = conn.Close()
	}
	if response == nil {
		t.Fatalf("Home mode handshake returned no HTTP response: %v", err)
	}
	defer response.Body.Close()
	body, errRead := io.ReadAll(response.Body)
	if errRead != nil {
		t.Fatalf("read Home response: %v", errRead)
	}
	if err == nil || response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("Home mode handshake = (%d, %v), want HTTP 503", response.StatusCode, err)
	}
	if !strings.Contains(string(body), "Gemini Live is not supported in Home mode") {
		t.Fatalf("Home mode response does not explain unsupported Gemini Live: %s", body)
	}
	geminiLiveTestAwait(t, completed)
}

func TestGeminiLivePayloadRulesAndMaskedSessionLog(t *testing.T) {
	for _, path := range []string{geminiLiveTestPath, "/v1beta" + geminiLiveTestPath} {
		t.Run(path, func(t *testing.T) {
			var output bytes.Buffer
			previousOutput := log.StandardLogger().Out
			log.SetOutput(&output)
			defer log.SetOutput(previousOutput)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn := geminiLiveTestUpgrade(t, w, r)
				if conn == nil {
					return
				}
				defer conn.Close()
				_, data, err := conn.ReadMessage()
				if err != nil {
					t.Errorf("read configured setup: %v", err)
					return
				}
				var payload struct {
					Setup struct {
						Model             string          `json:"model"`
						SystemInstruction json.RawMessage `json:"systemInstruction"`
						GenerationConfig  struct {
							Temperature float64 `json:"temperature"`
						} `json:"generationConfig"`
					} `json:"setup"`
				}
				if err := json.Unmarshal(data, &payload); err != nil {
					t.Errorf("decode configured setup: %v", err)
					return
				}
				if payload.Setup.Model != "models/"+geminiLiveTestModel || payload.Setup.GenerationConfig.Temperature != 0.2 || len(payload.Setup.SystemInstruction) != 0 {
					t.Errorf("payload rules were not final: %s", data)
				}
				if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"setupComplete":{}}`)); err != nil {
					t.Errorf("write setupComplete: %v", err)
					return
				}
				_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(1008, "upstream-key-0"))
			}))
			defer upstream.Close()
			cfg := &config.Config{Payload: config.PayloadConfig{
				Override: []config.PayloadRule{{
					Models: []config.PayloadModelRule{{Name: geminiLiveTestModel, Protocol: "gemini"}},
					Params: map[string]any{"generationConfig.temperature": 0.2},
				}},
				Filter: []config.PayloadFilterRule{{
					Models: []config.PayloadModelRule{{Name: geminiLiveTestModel, Protocol: "gemini"}},
					Params: []string{"systemInstruction"},
				}},
			}}
			url, completed := newGeminiLiveTestServer(t, cfg, upstream.URL, 1, geminiLiveTestModel)
			conn := geminiLiveTestDial(t, url+path+"?key="+geminiLiveTestClientKey, nil)
			geminiLiveTestWrite(t, conn, geminiLiveTestFrame{websocket.TextMessage, []byte(`{"setup":{"model":"models/` + geminiLiveTestModel + `","generationConfig":{"temperature":1},"systemInstruction":{"parts":[{"text":"filtered"}]}}}`)})
			geminiLiveTestRead(t, conn, geminiLiveTestFrame{websocket.TextMessage, []byte(`{"setupComplete":{}}`)})
			_, _, err := conn.ReadMessage()
			geminiLiveTestClose(t, err, 1008, "upstream-key-0")
			geminiLiveTestAwait(t, completed)
			text := output.String()
			if strings.Contains(text, geminiLiveTestClientKey) || strings.Contains(text, "upstream-key-0") {
				t.Fatalf("unmasked credentials in session log: %s", text)
			}
			if strings.Count(text, "gemini live session closed") != 1 || !strings.Contains(text, "credential=upst...ey-0") || !strings.Contains(text, "close_code=1008") || !strings.Contains(text, "duration=") {
				t.Fatalf("missing masked session summary: %s", text)
			}
		})
	}
}

func TestGeminiLiveClientDisconnectInterruptsSetup(t *testing.T) {
	setupReceived := make(chan struct{})
	upstreamClosed := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn := geminiLiveTestUpgrade(t, w, r)
		if conn == nil {
			return
		}
		defer conn.Close()
		if _, _, err := conn.ReadMessage(); err != nil {
			t.Errorf("read setup: %v", err)
			return
		}
		close(setupReceived)
		_, _, err := conn.ReadMessage()
		upstreamClosed <- err
	}))
	defer upstream.Close()
	url, completed := newGeminiLiveTestServer(t, &config.Config{}, upstream.URL, 1, geminiLiveTestModel)
	conn := geminiLiveTestDial(t, url+geminiLiveTestPath+"?key="+geminiLiveTestClientKey, nil)
	geminiLiveTestWrite(t, conn, geminiLiveTestFrame{websocket.TextMessage, []byte(`{"setup":{"model":"models/` + geminiLiveTestModel + `"}}`)})
	geminiLiveTestAwait(t, setupReceived)
	geminiLiveTestWrite(t, conn, geminiLiveTestFrame{websocket.CloseMessage, websocket.FormatCloseMessage(1000, "cancel setup")})
	geminiLiveTestClose(t, geminiLiveTestAwait(t, upstreamClosed), 1000, "cancel setup")
	geminiLiveTestAwait(t, completed)
}
