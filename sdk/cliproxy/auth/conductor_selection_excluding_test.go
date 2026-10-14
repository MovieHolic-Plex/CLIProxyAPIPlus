package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestManagerSelectAuthByKindExcludingRetriesSameModelWithoutCooldown(t *testing.T) {
	previous := quotaCooldownDisabled.Load()
	SetQuotaCooldownDisabled(true)
	t.Cleanup(func() { SetQuotaCooldownDisabled(previous) })

	const model = "gemini-3.5-transcribe-live"
	ctx := context.Background()
	manager := NewManager(nil, &FillFirstSelector{}, nil)
	manager.RegisterExecutor(schedulerTestExecutor{provider: "gemini"})
	for _, candidate := range []*Auth{
		{ID: "excluding-oauth", Provider: "gemini", Attributes: map[string]string{"priority": "100"}, Metadata: map[string]any{"access_token": "test-token"}},
		{ID: "excluding-unsupported", Provider: "gemini", Attributes: map[string]string{AttributeAPIKey: "test-unsupported", "priority": "90"}},
		{ID: "excluding-first", Provider: "gemini", Attributes: map[string]string{AttributeAPIKey: "test-first", "priority": "20"}},
		{ID: "excluding-second", Provider: "gemini", Attributes: map[string]string{AttributeAPIKey: "test-second", "priority": "10"}},
	} {
		if _, errRegister := manager.Register(ctx, candidate); errRegister != nil {
			t.Fatalf("Register(%s) error = %v", candidate.ID, errRegister)
		}
	}
	registerSchedulerModels(t, "gemini", model, "excluding-oauth", "excluding-first", "excluding-second")
	registerSchedulerModels(t, "gemini", "gemini-other-model", "excluding-unsupported")

	first, errSelect := manager.SelectAuthByKindExcluding(ctx, "gemini", model, AuthKindAPIKey, cliproxyexecutor.Options{}, nil)
	if errSelect != nil || first == nil || first.ID != "excluding-first" {
		t.Fatalf("initial selection = %#v, %v, want excluding-first", first, errSelect)
	}
	manager.MarkResult(ctx, Result{
		AuthID:   first.ID,
		Provider: "gemini",
		Model:    model,
		Error:    &Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota exceeded"},
	})

	// With cooling disabled, the original signature can still select the failed key.
	legacy, errSelect := manager.SelectAuthByKind(ctx, "gemini", model, " API-KEY ", cliproxyexecutor.Options{})
	if errSelect != nil || legacy == nil || legacy.ID != first.ID {
		t.Fatalf("legacy selection after failure = %#v, %v, want %s", legacy, errSelect, first.ID)
	}
	excluded := map[string]struct{}{first.ID: {}}
	second, errSelect := manager.SelectAuthByKindExcluding(ctx, "gemini", model, AuthKindAPIKey, cliproxyexecutor.Options{}, excluded)
	if errSelect != nil || second == nil || second.ID != "excluding-second" {
		t.Fatalf("retry selection = %#v, %v, want excluding-second", second, errSelect)
	}
	if len(excluded) != 1 {
		t.Fatalf("selection mutated exclusions: %#v", excluded)
	}
	if _, ok := excluded[first.ID]; !ok {
		t.Fatalf("selection removed excluded auth %s", first.ID)
	}
	excluded[second.ID] = struct{}{}
	selected, errSelect := manager.SelectAuthByKindExcluding(ctx, "gemini", model, AuthKindAPIKey, cliproxyexecutor.Options{}, excluded)
	var authErr *Error
	if selected != nil || !errors.As(errSelect, &authErr) || authErr.Code != "auth_not_found" {
		t.Fatalf("exhausted selection = %#v, %v, want auth_not_found rather than OAuth or another model", selected, errSelect)
	}
}

func TestManagerSelectAuthByKindExcludingRejectsIneligibleCredentials(t *testing.T) {
	const model = "gemini-3.5-transcribe-live"
	for _, tt := range []struct {
		name       string
		candidate  *Auth
		registered string
	}{
		{
			name:       "OAuth",
			candidate:  &Auth{ID: "excluding-only-oauth", Provider: "gemini", Metadata: map[string]any{"access_token": "test-token"}},
			registered: model,
		},
		{
			name:       "unsupported model",
			candidate:  &Auth{ID: "excluding-only-unsupported", Provider: "gemini", Attributes: map[string]string{AttributeAPIKey: "test-key"}},
			registered: "gemini-other-model",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			manager := NewManager(nil, &FillFirstSelector{}, nil)
			manager.RegisterExecutor(schedulerTestExecutor{provider: "gemini"})
			if _, errRegister := manager.Register(context.Background(), tt.candidate); errRegister != nil {
				t.Fatalf("Register() error = %v", errRegister)
			}
			registerSchedulerModels(t, "gemini", tt.registered, tt.candidate.ID)
			selected, errSelect := manager.SelectAuthByKindExcluding(context.Background(), "gemini", model, AuthKindAPIKey, cliproxyexecutor.Options{}, nil)
			var authErr *Error
			if selected != nil || !errors.As(errSelect, &authErr) || authErr.Code != "auth_not_found" {
				t.Fatalf("selection = %#v, %v, want auth_not_found", selected, errSelect)
			}
		})
	}
}

func TestManagerSelectAuthByKindExcludingPreservesValidation(t *testing.T) {
	for _, tt := range []struct {
		name       string
		home       bool
		kind       string
		code       string
		httpStatus int
	}{
		{name: "invalid kind", kind: "certificate", code: "invalid_auth_kind", httpStatus: http.StatusBadRequest},
		{name: "Home enabled", home: true, kind: AuthKindAPIKey, code: "home_unavailable", httpStatus: http.StatusServiceUnavailable},
	} {
		t.Run(tt.name, func(t *testing.T) {
			manager := NewManager(nil, nil, nil)
			manager.SetConfig(&internalconfig.Config{Home: internalconfig.HomeConfig{Enabled: tt.home}})
			selected, errSelect := manager.SelectAuthByKindExcluding(context.Background(), "gemini", "gemini-3.5-transcribe-live", tt.kind, cliproxyexecutor.Options{}, nil)
			var authErr *Error
			if selected != nil || !errors.As(errSelect, &authErr) || authErr.Code != tt.code || authErr.HTTPStatus != tt.httpStatus {
				t.Fatalf("selection = %#v, %v, want %s with HTTP %d", selected, errSelect, tt.code, tt.httpStatus)
			}
		})
	}
}
