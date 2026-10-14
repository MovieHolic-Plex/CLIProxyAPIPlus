package api

import (
	"net/http"
	"testing"
)

// TestForkOnlyRoutesRegistered guards fork-only public routes that upstream
// merges have silently dropped before (e.g. /v1/systemone lost in the v8 merge).
func TestForkOnlyRoutesRegistered(t *testing.T) {
	server := newTestServer(t)

	want := []struct{ method, path string }{
		{http.MethodPost, "/v1/systemone"},
		{http.MethodGet, "/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent"},
		{http.MethodGet, "/v1beta/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent"},
	}
	registered := make(map[string]bool)
	for _, route := range server.engine.Routes() {
		registered[route.Method+" "+route.Path] = true
	}
	for _, r := range want {
		if !registered[r.method+" "+r.path] {
			t.Errorf("fork-only route %s %s is not registered", r.method, r.path)
		}
	}
}
