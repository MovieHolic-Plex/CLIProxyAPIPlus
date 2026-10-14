// Package live relays the native Gemini Live protocol without model translation.
package live

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"
)

const Path = "/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent"

type Handler struct {
	manager    *auth.Manager
	loadConfig func() *config.Config
}

func NewHandler(manager *auth.Manager, loadConfig func() *config.Config) *Handler {
	return &Handler{manager: manager, loadConfig: loadConfig}
}

type frame struct {
	kind int
	data []byte
}

func (h *Handler) Handle(c *gin.Context) {
	// Access middleware can allow anonymous requests when no keys are configured;
	// this credential-bearing relay always requires an authenticated principal.
	if c.GetString("userApiKey") == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "API key required"})
		return
	}
	if h.manager == nil {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "Gemini auth manager unavailable"})
		return
	}
	if h.manager.HomeEnabled() {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "Gemini Live is not supported in Home mode"})
		return
	}
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	downstream, errUpgrade := upgrader.Upgrade(c.Writer, c.Request, nil)
	if errUpgrade != nil {
		return
	}
	started := time.Now()
	model, maskedCredential := "", ""
	finalErr := error(nil)
	defer func() {
		code, reason := closeDetails(finalErr)
		sendClose(downstream, code, reason)
		_ = downstream.Close()
		log.WithFields(log.Fields{
			"model": model, "credential": maskedCredential,
			"duration": time.Since(started), "close_code": code,
		}).Info("gemini live session closed")
	}()

	kind, setup, errRead := downstream.ReadMessage()
	if errRead != nil {
		finalErr = errRead
		return
	}
	model = setupModel(setup)
	if model == "" {
		finalErr = &websocket.CloseError{Code: websocket.ClosePolicyViolation, Text: "setup.model is required"}
		return
	}
	cfg := h.loadConfig()
	if cfg != nil && !sdkaccess.ModelAllowed(model, cfg.APIKeyModelWhitelists[c.GetString("userApiKey")]) {
		finalErr = &websocket.CloseError{Code: websocket.ClosePolicyViolation, Text: "model is not allowed for this API key"}
		return
	}
	// Native payload rules apply once, relative to setup, before any retry.
	// Validation may reject a changed model but must not undo a payload rule.
	setup = helps.ApplyPayloadConfigWithRequest(cfg, model, "gemini", "gemini", "setup", setup, setup, model, c.Request.URL.Path, c.Request.Header)
	if setupModel(setup) != model {
		finalErr = &websocket.CloseError{Code: websocket.ClosePolicyViolation, Text: "payload configuration changed setup.model"}
		return
	}
	ctx, cancel := context.WithCancelCause(c.Request.Context())
	frames := make(chan frame, 1)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			messageType, data, err := downstream.ReadMessage()
			if err != nil {
				cancel(err)
				return
			}
			select {
			case frames <- frame{messageType, data}:
			case <-ctx.Done():
				return
			}
		}
	}()
	defer func() {
		cancel(context.Canceled)
		_ = downstream.Close()
		<-readerDone
	}()

	excluded := make(map[string]struct{})
	// Bound retries to the credentials present when the session starts, even
	// if credentials are hot-reloaded while an upstream handshake is pending.
	attemptLimit := len(h.manager.List())
	finalErr = &websocket.CloseError{Code: websocket.CloseTryAgainLater, Text: "no eligible Gemini Live credential"}
	for attempt := 0; attempt < attemptLimit && ctx.Err() == nil; attempt++ {
		selected, errSelect := h.manager.SelectAuthByKindExcluding(ctx, "gemini", model, auth.AuthKindAPIKey, coreexecutor.Options{}, excluded)
		if errSelect != nil || selected == nil {
			break
		}
		excluded[selected.ID] = struct{}{}
		maskedCredential = util.HideAPIKey(selected.Attributes[auth.AttributeAPIKey])
		upstream, status, errDial := dial(ctx, cfg, selected)
		if errDial != nil {
			h.markResult(ctx, selected, model, status)
			finalErr = &websocket.CloseError{Code: websocket.CloseInternalServerErr, Text: "Gemini Live handshake failed"}
			continue
		}
		// Closing the client also interrupts an upstream still awaiting setupComplete.
		stopCancel := context.AfterFunc(ctx, func() {
			code, reason := closeDetails(context.Cause(ctx))
			sendClose(upstream, code, reason)
			_ = upstream.Close()
		})
		errSetup := upstream.WriteMessage(kind, setup)
		if errSetup == nil {
			errSetup = completeSetup(downstream, upstream)
		}
		if errSetup != nil {
			stopCancel()
			_ = upstream.Close()
			finalErr = errSetup
			if ctx.Err() == nil {
				code, _ := closeDetails(errSetup)
				h.markResult(ctx, selected, model, closeStatus(code))
			}
			continue
		}
		h.markResult(ctx, selected, model, http.StatusOK)
		// setupComplete has been relayed: no credential switching from here on.
		finalErr = relay(ctx, cancel, frames, downstream, upstream)
		stopCancel()
		_ = upstream.Close()
		break
	}
	if ctx.Err() != nil {
		finalErr = context.Cause(ctx)
	}
	// The reader cleanup runs before the final log/close defer, so send the
	// actual close here while the downstream connection is still open.
	code, reason := closeDetails(finalErr)
	sendClose(downstream, code, reason)
}

func (h *Handler) markResult(ctx context.Context, selected *auth.Auth, model string, status int) {
	result := auth.Result{
		AuthID: selected.ID, Provider: "gemini", Model: model, RouteModel: model,
		Success: status == http.StatusOK, CredentialVersion: selected.CredentialVersion,
		RegistrationEpoch: selected.RegistrationEpoch,
	}
	if !result.Success {
		// Never pass dial errors or upstream close reasons into logs: either may
		// contain an upstream URL, API key, or provider-supplied secret.
		result.Error = &auth.Error{Message: "Gemini Live setup failed", HTTPStatus: status}
	}
	h.manager.MarkResult(ctx, result)
}

func setupModel(data []byte) string {
	var message struct {
		Setup struct {
			Model string `json:"model"`
		} `json:"setup"`
	}
	if json.Unmarshal(data, &message) != nil {
		return ""
	}
	return strings.TrimPrefix(strings.TrimSpace(message.Setup.Model), "models/")
}

func completeSetup(downstream, upstream *websocket.Conn) error {
	for {
		kind, data, err := upstream.ReadMessage()
		if err != nil {
			return err
		}
		var message struct {
			SetupComplete json.RawMessage `json:"setupComplete"`
			Error         json.RawMessage `json:"error"`
		}
		if json.Unmarshal(data, &message) == nil && len(message.Error) > 0 {
			return &websocket.CloseError{Code: websocket.CloseInternalServerErr, Text: "Gemini Live setup rejected"}
		}
		if errWrite := downstream.WriteMessage(kind, data); errWrite != nil {
			return errWrite
		}
		if len(message.SetupComplete) > 0 && string(message.SetupComplete) != "null" {
			return nil
		}
	}
}

func dial(ctx context.Context, cfg *config.Config, selected *auth.Auth) (*websocket.Conn, int, error) {
	base := strings.TrimSpace(selected.Attributes["base_url"])
	if base == "" {
		base = "https://generativelanguage.googleapis.com"
	}
	target, errURL := url.Parse(base)
	if errURL != nil || target.Host == "" || target.User != nil {
		return nil, http.StatusBadGateway, errors.New("invalid Gemini base URL")
	}
	switch target.Scheme {
	case "https", "wss":
		target.Scheme = "wss"
	case "http", "ws":
		target.Scheme = "ws"
	default:
		return nil, http.StatusBadGateway, errors.New("invalid Gemini base URL scheme")
	}
	target.Path, target.RawPath, target.Fragment = Path, "", ""
	query := make(url.Values)
	query.Set("key", selected.Attributes[auth.AttributeAPIKey])
	target.RawQuery = query.Encode()
	dialer := websocket.Dialer{Proxy: http.ProxyFromEnvironment}
	proxyURL := strings.TrimSpace(selected.ProxyURL)
	if proxyURL == "" && cfg != nil {
		proxyURL = strings.TrimSpace(cfg.ProxyURL)
	}
	if proxyURL != "" {
		setting, errProxy := proxyutil.Parse(proxyURL)
		if errProxy != nil {
			return nil, http.StatusBadGateway, errors.New("invalid Gemini proxy configuration")
		}
		switch setting.Mode {
		case proxyutil.ModeDirect:
			dialer.Proxy = nil
		case proxyutil.ModeProxy:
			proxyDialer, _, errBuild := proxyutil.BuildDialer(proxyURL)
			if errBuild != nil {
				return nil, http.StatusBadGateway, errors.New("invalid Gemini proxy configuration")
			}
			contextDialer, ok := proxyDialer.(proxy.ContextDialer)
			if !ok {
				return nil, http.StatusBadGateway, errors.New("Gemini proxy does not support context dialing")
			}
			dialer.Proxy = nil
			dialer.NetDialContext = contextDialer.DialContext
		default:
			return nil, http.StatusBadGateway, errors.New("invalid Gemini proxy configuration")
		}
	}
	headers := make(http.Header)
	util.ApplyCustomHeadersFromAttrs(&http.Request{Header: headers}, selected.Attributes)
	headers.Del("Authorization")
	headers.Set("x-goog-api-key", selected.Attributes[auth.AttributeAPIKey])
	conn, response, errDial := dialer.DialContext(ctx, target.String(), headers)
	status := http.StatusBadGateway
	if response != nil {
		status = response.StatusCode
		if response.Body != nil {
			_ = response.Body.Close()
		}
	}
	return conn, status, errDial
}

func relay(ctx context.Context, cancel context.CancelCauseFunc, frames <-chan frame, downstream, upstream *websocket.Conn) error {
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for {
			select {
			case <-ctx.Done():
				return
			case next := <-frames:
				if err := upstream.WriteMessage(next.kind, next.data); err != nil {
					cancel(err)
					return
				}
			}
		}
	}()
	var result error
	for {
		kind, data, errRead := upstream.ReadMessage()
		if errRead != nil {
			result = errRead
			break
		}
		if errWrite := downstream.WriteMessage(kind, data); errWrite != nil {
			result = errWrite
			break
		}
	}
	if ctx.Err() != nil {
		result = context.Cause(ctx)
	}
	code, reason := closeDetails(result)
	sendClose(downstream, code, reason)
	sendClose(upstream, code, reason)
	cancel(result)
	_ = upstream.Close()
	<-writerDone
	return result
}

func sendClose(conn *websocket.Conn, code int, reason string) {
	_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), time.Time{})
}

func closeDetails(err error) (int, string) {
	var closeErr *websocket.CloseError
	if errors.As(err, &closeErr) {
		switch closeErr.Code {
		case websocket.CloseAbnormalClosure, websocket.CloseNoStatusReceived, websocket.CloseTLSHandshake:
			return websocket.CloseInternalServerErr, "connection closed without a close frame"
		default:
			return closeErr.Code, closeErr.Text
		}
	}
	return websocket.CloseInternalServerErr, "Gemini Live connection closed"
}

func closeStatus(code int) int {
	switch code {
	case websocket.ClosePolicyViolation:
		return http.StatusForbidden
	case websocket.CloseTryAgainLater:
		return http.StatusTooManyRequests
	case websocket.CloseInternalServerErr:
		return http.StatusServiceUnavailable
	default:
		return http.StatusBadGateway
	}
}
