package executor

import (
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func TestOpenAICompatForAPIKeySharesDeveloperRoleCache(t *testing.T) {
	cfg := &config.Config{
		SDKConfig: config.SDKConfig{
			OAuthOnlyFields: map[string]bool{"codex-header-defaults.user-agent": true},
		},
	}
	cfg.CodexHeaderDefaults.UserAgent = "oauth-agent"
	executor := NewOpenAICompatExecutor("compat", cfg)
	executor.now = func() time.Time { return time.Unix(100, 0) }

	first := executor.ForAPIKey().(*OpenAICompatExecutor)
	second := executor.ForAPIKey().(*OpenAICompatExecutor)
	if first == executor || first == second || first.provider != executor.provider {
		t.Fatal("API-key binding must create independent executor views for the same provider")
	}
	if first.cfg.CodexHeaderDefaults.UserAgent != "" || cfg.CodexHeaderDefaults.UserAgent != "oauth-agent" {
		t.Fatal("API-key binding must scope configuration without mutating the original")
	}
	key := openAICompatDeveloperRoleCapabilityKey{identity: "compat", model: "test"}
	first.developerRoleCacheInstance().add(key)
	if !second.developerRoleCacheInstance().contains(key) || !executor.developerRoleCacheInstance().contains(key) {
		t.Fatal("API-key views must share learned developer-role capabilities")
	}
}
