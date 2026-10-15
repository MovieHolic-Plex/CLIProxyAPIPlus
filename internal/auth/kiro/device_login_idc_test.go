package kiro

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func newIDCTestClient(serverURL string) *DeviceLoginClient {
	return NewDeviceLoginClient(&config.Config{
		OAuthEndpointOverrides: map[string]config.OAuthEndpointConfig{
			"kiro": {ApiBaseURL: serverURL},
		},
	})
}

func TestParseDeviceLoginKindAcceptsIdentityCenterAliases(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"idc", "IDC", "organization", "org", "aws-idc", "identity-center", "iam-identity-center"} {
		got, err := ParseDeviceLoginKind(raw)
		if err != nil {
			t.Fatalf("ParseDeviceLoginKind(%q): %v", raw, err)
		}
		if got != DeviceLoginIDC {
			t.Fatalf("ParseDeviceLoginKind(%q) = %q, want %q", raw, got, DeviceLoginIDC)
		}
	}
}

func TestNormalizeIDCStartURL(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"":                                "",
		"   ":                             "",
		"not a url":                       "",
		"ftp://acme.awsapps.com/start":    "",
		"https://acme.awsapps.com/start":  "https://acme.awsapps.com/start",
		"https://acme.awsapps.com/start/": "https://acme.awsapps.com/start",
		"https://acme.awsapps.com/":       "https://acme.awsapps.com/start",
		"https://acme.awsapps.com/portal": "https://acme.awsapps.com/portal/start",
		"https://acme.awsapps.com/start?x=1#/device": "https://acme.awsapps.com/start",
	}
	for raw, want := range cases {
		if got := normalizeIDCStartURL(raw); got != want {
			t.Fatalf("normalizeIDCStartURL(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestBuildIDCDeviceURL(t *testing.T) {
	t.Parallel()
	got := buildIDCDeviceURL("https://acme.awsapps.com/start", "WXYZ-9999")
	want := "https://acme.awsapps.com/start/#/device?user_code=WXYZ-9999"
	if got != want {
		t.Fatalf("buildIDCDeviceURL = %q, want %q", got, want)
	}
	// A user code needing escapes must be escaped exactly once, and the portal
	// reads it back with a JS-style decoder (percent escapes only, so a literal
	// "+" stays a plus rather than turning into a space).
	escaped := buildIDCDeviceURL("https://acme.awsapps.com/start", "A B+C")
	parsedEscaped, err := url.Parse(escaped)
	if err != nil {
		t.Fatalf("parse built URL: %v", err)
	}
	_, rawQuery, found := strings.Cut(parsedEscaped.Fragment, "?")
	if !found {
		t.Fatalf("fragment carries no query: %q", parsedEscaped.Fragment)
	}
	rawValue, _, found := strings.Cut(rawQuery, "user_code=")
	if !found || rawValue != "" {
		t.Fatalf("fragment query = %q", rawQuery)
	}
	decoded, err := url.PathUnescape(rawQuery[len("user_code="):])
	if err != nil {
		t.Fatalf("decode fragment: %v", err)
	}
	if decoded != "A B+C" {
		t.Fatalf("user code round trip = %q from %q", decoded, escaped)
	}
	if buildIDCDeviceURL("", "CODE") != "" || buildIDCDeviceURL("https://acme.awsapps.com/start", "") != "" {
		t.Fatal("missing inputs must produce no URL")
	}
}

func TestStartIDCUsesPortalStartURLAndPortalDevicePage(t *testing.T) {
	var registerBody, deviceBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/client/register":
			if err := json.NewDecoder(r.Body).Decode(&registerBody); err != nil {
				t.Errorf("decode register: %v", err)
			}
			_, _ = io.WriteString(w, `{"clientId":"idc-cid","clientSecret":"idc-csec"}`)
		case "/device_authorization":
			if err := json.NewDecoder(r.Body).Decode(&deviceBody); err != nil {
				t.Errorf("decode device authorization: %v", err)
			}
			_, _ = io.WriteString(w, `{
				"deviceCode":"idc-dev",
				"userCode":"WXYZ-9999",
				"verificationUri":"https://device.sso.eu-west-1.amazonaws.com/",
				"verificationUriComplete":"https://view.awsapps.com/start/#/device?user_code=WXYZ-9999",
				"expiresIn":600,
				"interval":5
			}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	flow, err := newIDCTestClient(server.URL).StartIDC(context.Background(), "https://acme.awsapps.com/start/?ignored=1", "eu-west-1")
	if err != nil {
		t.Fatalf("StartIDC: %v", err)
	}
	if registerBody["clientName"] != kiroDeviceIDCClientName || registerBody["clientType"] != "public" {
		t.Fatalf("register body = %#v", registerBody)
	}
	scopes, _ := registerBody["scopes"].([]any)
	if len(scopes) != len(kiroDeviceIDCScopes) {
		t.Fatalf("register scopes = %#v", registerBody["scopes"])
	}
	grants, _ := registerBody["grantTypes"].([]any)
	if len(grants) != 2 {
		t.Fatalf("register grantTypes = %#v", registerBody["grantTypes"])
	}
	// The portal URL is normalized and sent verbatim; the query string is dropped.
	if deviceBody["startUrl"] != "https://acme.awsapps.com/start" || deviceBody["clientId"] != "idc-cid" {
		t.Fatalf("device authorization body = %#v", deviceBody)
	}
	// AWS returns the Builder ID device page, which cannot finish an Identity
	// Center sign-in, so the portal device URL must win.
	if flow.VerificationURIComplete != "https://acme.awsapps.com/start/#/device?user_code=WXYZ-9999" {
		t.Fatalf("verification URL = %q", flow.VerificationURIComplete)
	}
	if flow.VerificationURI != "https://device.sso.eu-west-1.amazonaws.com/" {
		t.Fatalf("verification URI = %q", flow.VerificationURI)
	}
	if flow.Kind != DeviceLoginIDC || flow.Region != "eu-west-1" || flow.StartURL != "https://acme.awsapps.com/start" {
		t.Fatalf("flow = %+v", flow)
	}
	if flow.ClientID != "idc-cid" || flow.ClientSecret != "idc-csec" || flow.UserCode != "WXYZ-9999" {
		t.Fatalf("flow credentials = %+v", flow)
	}
	if flow.ExpiresIn != 10*time.Minute || flow.Interval != 5*time.Second {
		t.Fatalf("flow timings = %+v", flow)
	}
}

func TestStartIDCDefaultsRegionAndRejectsBadStartURL(t *testing.T) {
	client := newIDCTestClient("http://127.0.0.1:1")
	if _, err := client.StartIDC(context.Background(), "", "eu-west-1"); err == nil {
		t.Fatal("expected an error for a missing start URL")
	}
	if _, err := client.StartIDC(context.Background(), "https://acme.awsapps.com/start", "not-a-region"); err == nil {
		t.Fatal("expected the invalid region to fall back and the request to fail")
	}
}

func TestPollIDCReturnsIdentityCenterToken(t *testing.T) {
	var tokenBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&tokenBody); err != nil {
			t.Errorf("decode token: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"accessToken":"at-idc","refreshToken":"rt-idc","expiresIn":1800}`)
	}))
	t.Cleanup(server.Close)

	flow := &DeviceLoginFlow{
		Kind:         DeviceLoginIDC,
		DeviceCode:   "idc-dev",
		ClientID:     "idc-cid",
		ClientSecret: "idc-csec",
		Region:       "eu-west-1",
		StartURL:     "https://acme.awsapps.com/start",
	}
	token, err := newIDCTestClient(server.URL).Poll(context.Background(), flow)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if tokenBody["grantType"] != "urn:ietf:params:oauth:grant-type:device_code" || tokenBody["deviceCode"] != "idc-dev" {
		t.Fatalf("token body = %#v", tokenBody)
	}
	if token.AuthMethod != "idc" || token.StartURL != flow.StartURL || token.Region != "eu-west-1" {
		t.Fatalf("token = %+v", token)
	}
	if token.AccessToken != "at-idc" || token.RefreshToken != "rt-idc" || token.ClientID != "idc-cid" || token.ClientSecret != "idc-csec" {
		t.Fatalf("token credentials = %+v", token)
	}
	data := token.ToTokenData()
	if data.AuthMethod != "idc" || data.StartURL != flow.StartURL || data.Region != "eu-west-1" {
		t.Fatalf("token data = %+v", data)
	}
}
