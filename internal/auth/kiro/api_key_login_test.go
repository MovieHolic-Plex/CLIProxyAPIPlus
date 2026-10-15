package kiro

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func withAPIKeyBase(t *testing.T, base string) {
	t.Helper()
	previous := kiroAPIKeyManagementBase
	kiroAPIKeyManagementBase = func(string) string { return base }
	t.Cleanup(func() { kiroAPIKeyManagementBase = previous })
}

func TestIsKiroAPIKey(t *testing.T) {
	t.Parallel()
	for _, token := range []string{"ksk_abc", " ksk_abc "} {
		if !IsKiroAPIKey(token) {
			t.Fatalf("IsKiroAPIKey(%q) = false", token)
		}
	}
	for _, token := range []string{"", "abc", "https://example.com", "KSK_abc"} {
		if IsKiroAPIKey(token) {
			t.Fatalf("IsKiroAPIKey(%q) = true", token)
		}
	}
}

func TestResolveKiroAPIKeyProfileSendsKeyContract(t *testing.T) {
	var target, tokenType, contentType, authorization string
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target = r.Header.Get("X-Amz-Target")
		tokenType = r.Header.Get("tokentype")
		contentType = r.Header.Get("Content-Type")
		authorization = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"profile":{"arn":"arn:aws:codewhisperer:eu-central-1:123456789012:profile/AAAA"}}`)
	}))
	t.Cleanup(server.Close)
	withAPIKeyBase(t, server.URL)

	arn, err := ResolveKiroAPIKeyProfile(context.Background(), nil, " ksk_abc ", "")
	if err != nil {
		t.Fatalf("ResolveKiroAPIKeyProfile: %v", err)
	}
	if arn != "arn:aws:codewhisperer:eu-central-1:123456789012:profile/AAAA" {
		t.Fatalf("profile arn = %q", arn)
	}
	if target != "AmazonCodeWhispererService.GetProfile" {
		t.Fatalf("X-Amz-Target = %q", target)
	}
	if tokenType != "API_KEY" {
		t.Fatalf("tokentype = %q", tokenType)
	}
	if contentType != "application/x-amz-json-1.0" {
		t.Fatalf("Content-Type = %q", contentType)
	}
	if authorization != "Bearer ksk_abc" {
		t.Fatalf("Authorization = %q", authorization)
	}
	if body != "{}" {
		t.Fatalf("body = %q", body)
	}
}

func TestResolveKiroAPIKeyProfileRejectsBadKeys(t *testing.T) {
	// A value that is not a Kiro key must never reach the network.
	withAPIKeyBase(t, "http://127.0.0.1:1")
	if _, err := ResolveKiroAPIKeyProfile(context.Background(), nil, "not-a-key", ""); err == nil {
		t.Fatal("expected an error for a value that is not a Kiro API key")
	}

	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"rejected", http.StatusUnauthorized, `{"message":"Invalid token"}`},
		{"forbidden", http.StatusForbidden, ``},
		{"server error", http.StatusInternalServerError, ``},
		{"no profile", http.StatusOK, `{}`},
		{"invalid json", http.StatusOK, `not-json`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			t.Cleanup(server.Close)
			withAPIKeyBase(t, server.URL)

			if _, err := ResolveKiroAPIKeyProfile(context.Background(), nil, "ksk_abc", ""); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestResolveKiroAPIKeyRegion(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		profileArn string
		fallback   string
		want       string
	}{
		{"profile arn wins", "arn:aws:codewhisperer:eu-central-1:1:profile/A", "us-west-2", "eu-central-1"},
		{"fallback when arn has no region", "not-an-arn", "us-west-2", "us-west-2"},
		{"default when nothing is usable", "not-an-arn", "bogus", "us-east-1"},
	}
	for _, tc := range cases {
		if got := ResolveKiroAPIKeyRegion(tc.profileArn, tc.fallback); got != tc.want {
			t.Fatalf("%s: ResolveKiroAPIKeyRegion = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// An API key must survive JSON round-tripping through the auth-file storage shape.
func TestKiroAPIKeyStorageRoundTrip(t *testing.T) {
	t.Parallel()
	profileArn := "arn:aws:codewhisperer:eu-central-1:1:profile/A"
	region := ResolveKiroAPIKeyRegion(profileArn, "")
	token := &DeviceLoginToken{
		AccessToken: "ksk_abc",
		ProfileArn:  profileArn,
		Region:      region,
		ExpiresIn:   KiroAPIKeyLifetimeSeconds,
		AuthMethod:  "apikey",
		Provider:    "AWS",
	}
	data := token.ToTokenData()
	fileName := GenerateTokenFileName(data)
	if !strings.Contains(fileName, "apikey") {
		t.Fatalf("file name = %q", fileName)
	}
	storage := &KiroTokenStorage{
		Type:        "kiro",
		AccessToken: data.AccessToken,
		ProfileArn:  data.ProfileArn,
		ExpiresAt:   data.ExpiresAt,
		AuthMethod:  data.AuthMethod,
		Provider:    data.Provider,
		Region:      data.Region,
	}
	encoded, err := json.Marshal(storage)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded KiroTokenStorage
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.AuthMethod != "apikey" || decoded.AccessToken != "ksk_abc" || decoded.Region != "eu-central-1" {
		t.Fatalf("round trip = %+v", decoded)
	}
	if decoded.ToTokenData().AuthMethod != "apikey" {
		t.Fatal("auth method was lost in the storage conversion")
	}
}
