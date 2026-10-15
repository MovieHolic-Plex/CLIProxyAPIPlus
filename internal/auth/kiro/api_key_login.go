package kiro

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
	log "github.com/sirupsen/logrus"
)

const (
	// kiroAPIKeyPrefix identifies a Kiro API key. Keys are issued per profile and
	// carry no refresh token, so they behave differently from login flows.
	kiroAPIKeyPrefix = "ksk_"
	// kiroAPIKeyDefaultRegion is the control plane that issues and validates keys.
	kiroAPIKeyDefaultRegion = "us-east-1"
	// kiroAPIKeyTimeout bounds credential acquisition only.
	kiroAPIKeyTimeout = 30 * time.Second
	// KiroAPIKeyLifetimeSeconds is the expiry recorded for an API-key credential.
	// The key stays valid until Kiro revokes it, so this is a placeholder: the
	// refresh sweep skips apikey credentials entirely.
	KiroAPIKeyLifetimeSeconds = 365 * 24 * 60 * 60
)

// kiroAPIKeyManagementBase returns the Kiro management endpoint a key is
// validated against. It is a variable so tests can point it at a local server.
var kiroAPIKeyManagementBase = func(region string) string {
	return fmt.Sprintf("https://management.%s.kiro.dev/", region)
}

// ErrKiroAPIKeyRejected marks a key the Kiro control plane refused, as opposed
// to a transient failure while validating it.
var ErrKiroAPIKeyRejected = errors.New("kiro api key rejected")

// IsKiroAPIKey reports whether a credential is a Kiro API key rather than a
// bearer token obtained through a login flow.
func IsKiroAPIKey(token string) bool {
	return strings.HasPrefix(strings.TrimSpace(token), kiroAPIKeyPrefix)
}

// ResolveKiroAPIKeyProfile validates an API key against the Kiro management
// endpoint and returns the profile ARN it belongs to, which the runtime needs to
// address the account. region is the control-plane region to validate against
// and defaults to us-east-1, the region Kiro issues keys for.
func ResolveKiroAPIKeyProfile(ctx context.Context, cfg *config.Config, apiKey, region string) (string, error) {
	key := strings.TrimSpace(apiKey)
	if !IsKiroAPIKey(key) {
		return "", fmt.Errorf("kiro api key must start with %s", kiroAPIKeyPrefix)
	}
	apiRegion := NormalizeKiroRegion(region)
	if apiRegion == "" {
		apiRegion = kiroAPIKeyDefaultRegion
	}

	client := &http.Client{Timeout: kiroAPIKeyTimeout}
	if cfg != nil {
		client = util.SetProxy(&cfg.SDKConfig, client)
	}

	// GetProfile with an empty body returns the profile that owns the key.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		kiroAPIKeyManagementBase(apiRegion), bytes.NewReader([]byte("{}")))
	if err != nil {
		return "", fmt.Errorf("build kiro api key request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.0")
	req.Header.Set("X-Amz-Target", "AmazonCodeWhispererService.GetProfile")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("tokentype", "API_KEY")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("validate kiro api key: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Errorf("kiro: close api key response body: %v", closeErr)
		}
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read kiro api key response: %w", err)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", fmt.Errorf("%w (status %d)", ErrKiroAPIKeyRejected, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("validate kiro api key failed (status %d)", resp.StatusCode)
	}

	var payload struct {
		Profile struct {
			Arn string `json:"arn"`
		} `json:"profile"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("parse kiro api key response: %w", err)
	}
	profileArn := strings.TrimSpace(payload.Profile.Arn)
	if profileArn == "" {
		return "", fmt.Errorf("%w: the key is not associated with a profile", ErrKiroAPIKeyRejected)
	}
	return profileArn, nil
}

// ResolveKiroAPIKeyRegion returns the runtime region for an API-key credential,
// preferring the region named by the profile ARN and falling back to the
// control-plane region the key was validated against.
func ResolveKiroAPIKeyRegion(profileArn, fallback string) string {
	if arnRegion := NormalizeKiroRegion(ExtractRegionFromProfileArn(profileArn)); arnRegion != "" {
		return arnRegion
	}
	if region := NormalizeKiroRegion(fallback); region != "" {
		return region
	}
	return kiroAPIKeyDefaultRegion
}
