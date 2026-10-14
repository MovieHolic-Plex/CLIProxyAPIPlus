package executor

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
)

// antigravityNonStreamSSE is the SSE-framed body cloudcode-pa returns for
// streamGenerateContent?alt=sse, which non-stream Execute now requests.
const antigravityNonStreamSSE = "data: {\"response\":{\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"o\"}]}}],\"modelVersion\":\"gemini-3.8-flash\",\"responseId\":\"resp-sse\"},\"traceId\":\"trace-sse\"}\n\n" +
	"data: {\"response\":{\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"k\"}]},\"finishReason\":\"STOP\"}],\"modelVersion\":\"gemini-3.8-flash\",\"responseId\":\"resp-sse\",\"usageMetadata\":{\"promptTokenCount\":5,\"candidatesTokenCount\":1,\"totalTokenCount\":6}}}\n\n"

func TestAntigravityExecuteNonStreamParsesSSEFramedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, antigravityNonStreamSSE)
	}))
	defer server.Close()

	executor := NewAntigravityExecutor(&config.Config{RequestRetry: 1})
	resp, errExecute := executor.Execute(context.Background(), &cliproxyauth.Auth{
		Metadata: map[string]any{
			"access_token": "token-123",
			"expired":      time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			"project_id":   "project-1",
		},
		Attributes: map[string]string{"base_url": server.URL},
	}, cliproxyexecutor.Request{
		Model:   "gemini-3.8-flash",
		Payload: []byte(`{"model":"gemini-3.8-flash","messages":[{"role":"user","content":"say ok"}]}`),
	}, cliproxyexecutor.Options{
		SourceFormat:   sdktranslator.FromString("openai"),
		ResponseFormat: sdktranslator.FromString("openai"),
	})
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}

	if got := gjson.GetBytes(resp.Payload, "choices.0.message.content").String(); got != "ok" {
		t.Fatalf("content = %q, want %q; payload = %s", got, "ok", resp.Payload)
	}
	if got := gjson.GetBytes(resp.Payload, "usage.total_tokens").Int(); got != 6 {
		t.Fatalf("usage.total_tokens = %d, want 6; payload = %s", got, resp.Payload)
	}
}
