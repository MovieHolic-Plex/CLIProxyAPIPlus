package kiro

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
)

// kiro-cli stores Identity Center (organization) credentials under the "odic"
// spelling with the device registration next to them, and Builder ID uses the
// same keys without a profile. Importing that pair is the supported path for
// organization accounts whose Identity Center rejects the device-code flow, so
// both spellings must keep resolving and the profile must decide idc vs
// builder-id exactly as the refresh dispatcher expects.
func TestLoadKiroCLICredentialAcceptsODICKeySpelling(t *testing.T) {
	t.Parallel()

	for _, prefix := range []string{"kirocli:odic:", "kirocli:oidc:", "codewhisperer:odic:"} {
		for _, tc := range []struct {
			name       string
			profileArn string
			wantMethod string
		}{
			{name: "organization profile", profileArn: "arn:aws:codewhisperer:ap-southeast-2:123456789012:profile/test", wantMethod: "idc"},
			{name: "no profile", profileArn: "", wantMethod: "builder-id"},
		} {
			t.Run(prefix+tc.name, func(t *testing.T) {
				t.Parallel()

				path := filepath.Join(t.TempDir(), "data.sqlite3")
				db, err := sql.Open("sqlite", path)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				if _, err := db.Exec(`CREATE TABLE auth_kv (key TEXT PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(`CREATE TABLE state (key TEXT PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
					t.Fatal(err)
				}

				tokenJSON, _ := json.Marshal(map[string]any{
					"accessToken":  "odic-access",
					"refreshToken": "odic-refresh",
					"expiresAt":    "2030-01-02T03:04:05Z",
					"region":       "eu-west-1",
					"startUrl":     "https://acme.awsapps.com/start",
				})
				registrationJSON, _ := json.Marshal(map[string]any{
					"clientId":     "odic-client",
					"clientSecret": "odic-secret",
				})
				for key, value := range map[string]string{
					prefix + "token":               string(tokenJSON),
					prefix + "device-registration": string(registrationJSON),
				} {
					if _, err := db.Exec(`INSERT INTO auth_kv(key, value) VALUES(?, ?)`, key, value); err != nil {
						t.Fatal(err)
					}
				}
				if tc.profileArn != "" {
					profileJSON, _ := json.Marshal(map[string]any{"arn": tc.profileArn})
					if _, err := db.Exec(`INSERT INTO state(key, value) VALUES(?, ?)`, "api.codewhisperer.profile", string(profileJSON)); err != nil {
						t.Fatal(err)
					}
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}

				got, err := LoadKiroCLICredential(path, "")
				if err != nil {
					t.Fatalf("LoadKiroCLICredential: %v", err)
				}
				if got.AuthMethod != tc.wantMethod {
					t.Fatalf("auth method = %q, want %q", got.AuthMethod, tc.wantMethod)
				}
				if got.ClientID != "odic-client" || got.ClientSecret != "odic-secret" {
					t.Fatalf("registration = %q/%q", got.ClientID, got.ClientSecret)
				}
				if got.Region != "eu-west-1" || got.StartURL != "https://acme.awsapps.com/start" {
					t.Fatalf("region/startUrl = %q/%q", got.Region, got.StartURL)
				}
				if tc.profileArn != "" && got.ProfileArn != tc.profileArn {
					t.Fatalf("profile arn = %q", got.ProfileArn)
				}
			})
		}
	}
}
