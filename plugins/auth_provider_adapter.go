package plugins

import (
	"context"
	"sort"

	"github.com/navidrome/navidrome/core/auth"
	"github.com/navidrome/navidrome/log"
	"github.com/navidrome/navidrome/model"
	"github.com/navidrome/navidrome/plugins/capabilities"
	"github.com/navidrome/navidrome/server/events"
)

// CapabilityAuthProvider indicates the plugin can act as an external
// authentication/identity provider. Detected when the plugin exports at least
// one of the auth provider functions.
const CapabilityAuthProvider Capability = "AuthProvider"

// Auth provider function names (snake_case as per design)
const (
	FuncAuthGetStatus    = "nd_auth_get_status"
	FuncAuthGetLoginURL  = "nd_auth_get_login_url"
	FuncAuthExchangeCode = "nd_auth_exchange_code"
	FuncAuthVerifyBearer = "nd_auth_verify_bearer"
	FuncAuthGetLogoutURL = "nd_auth_get_logout_url"
)

func init() {
	registerCapability(
		CapabilityAuthProvider,
		FuncAuthGetStatus,
		FuncAuthGetLoginURL,
		FuncAuthExchangeCode,
		FuncAuthVerifyBearer,
		FuncAuthGetLogoutURL,
	)
}

func newAuthProviderPlugin(p *plugin) *AuthProviderPlugin {
	return &AuthProviderPlugin{
		name:   p.name,
		plugin: p,
	}
}

// AuthProviderPlugin is an adapter that wraps an Extism plugin implementing the
// auth_provider capability. The host (Navidrome) keeps responsibility for HTTP
// routing, CSRF state cookies, user provisioning and JWT session creation; the
// plugin performs all protocol-level work (discovery, token exchange, token
// verification and claim extraction).
type AuthProviderPlugin struct {
	name   string
	plugin *plugin
}

// Enabled reports whether the provider is fully configured and can handle logins.
func (p *AuthProviderPlugin) Enabled(ctx context.Context) bool {
	status, err := p.GetStatus(ctx, "")
	return err == nil && status.Enabled
}

// GetStatus returns the provider's current status and public configuration.
func (p *AuthProviderPlugin) GetStatus(ctx context.Context, appURL string) (capabilities.AuthStatus, error) {
	input := capabilities.GetStatusRequest{AppURL: appURL}
	return callPluginFunction[capabilities.GetStatusRequest, capabilities.AuthStatus](ctx, p.plugin, FuncAuthGetStatus, input)
}

// GetLoginURL generates the authorization URL to start a login flow.
func (p *AuthProviderPlugin) GetLoginURL(ctx context.Context, state, nonce, redirectURI string) (string, error) {
	input := capabilities.GetLoginURLRequest{
		State:       state,
		Nonce:       nonce,
		RedirectURI: redirectURI,
	}
	result, err := callPluginFunction[capabilities.GetLoginURLRequest, capabilities.GetLoginURLResponse](ctx, p.plugin, FuncAuthGetLoginURL, input)
	if err != nil {
		return "", err
	}
	return result.AuthorizationURL, nil
}

// ExchangeCode trades an authorization code for an authenticated identity.
func (p *AuthProviderPlugin) ExchangeCode(ctx context.Context, code, state, nonce, redirectURI string) (capabilities.AuthIdentity, error) {
	input := capabilities.ExchangeCodeRequest{
		Code:        code,
		State:       state,
		Nonce:       nonce,
		RedirectURI: redirectURI,
	}
	return callPluginFunction[capabilities.ExchangeCodeRequest, capabilities.AuthIdentity](ctx, p.plugin, FuncAuthExchangeCode, input)
}

// VerifyBearer validates a bearer token (e.g. an OIDC ID token) from an API client.
func (p *AuthProviderPlugin) VerifyBearer(ctx context.Context, token string) (capabilities.AuthIdentity, error) {
	input := capabilities.VerifyBearerRequest{Token: token}
	return callPluginFunction[capabilities.VerifyBearerRequest, capabilities.AuthIdentity](ctx, p.plugin, FuncAuthVerifyBearer, input)
}

// GetLogoutURL returns the provider's single sign-out URL.
func (p *AuthProviderPlugin) GetLogoutURL(ctx context.Context, postLogoutRedirectURI, idTokenHint string) (string, error) {
	input := capabilities.GetLogoutURLRequest{
		PostLogoutRedirectURI: postLogoutRedirectURI,
		IDTokenHint:           idTokenHint,
	}
	result, err := callPluginFunction[capabilities.GetLogoutURLRequest, capabilities.GetLogoutURLResponse](ctx, p.plugin, FuncAuthGetLogoutURL, input)
	if err != nil {
		return "", err
	}
	return result.LogoutURL, nil
}

// ToIdentity converts a plugin identity into the core auth.Identity, carrying
// over the IsAdmin and IDToken fields used by the auth router.
func (p *AuthProviderPlugin) ToIdentity(ctx context.Context, ai capabilities.AuthIdentity) *auth.Identity {
	return &auth.Identity{
		Provider:    ai.Provider,
		Subject:     ai.Subject,
		Username:    ai.Username,
		Email:       ai.Email,
		DisplayName: ai.DisplayName,
		Groups:      ai.Groups,
		Claims:      ai.Claims,
		IsAdmin:     ai.IsAdmin,
		IDToken:     ai.IDToken,
	}
}

// LoadAuthProvider returns a loaded auth provider plugin by name.
func (m *Manager) LoadAuthProvider(name string) (*AuthProviderPlugin, bool) {
	return loadPlugin(m, name, CapabilityAuthProvider, newAuthProviderPlugin)
}

// ActiveAuthProvider returns the single currently active auth provider plugin.
// Only one provider is supported at a time; the first enabled auth_provider
// plugin is returned.
func (m *Manager) ActiveAuthProvider(ctx context.Context) (*AuthProviderPlugin, bool) {
	m.mu.RLock()
	var names []string
	for name, p := range m.plugins {
		if hasCapability(p.capabilities, CapabilityAuthProvider) {
			names = append(names, name)
		}
	}
	m.mu.RUnlock()

	sort.Strings(names)
	for _, name := range names {
		provider, ok := m.LoadAuthProvider(name)
		if !ok {
			continue
		}
		if provider.Enabled(ctx) {
			log.Info(ctx, "Active auth provider", "provider", name)
			return provider, true
		}
	}
	return nil, false
}

// AuthenticateBearer validates a bearer token against the single active auth
// provider plugin and returns the corresponding identity. It returns an error
// when no auth provider plugin is active or the token cannot be verified.
func AuthenticateBearer(ctx context.Context, ds model.DataStore, token string) (*auth.Identity, error) {
	m := GetManager(ds, events.GetBroker(), nil)
	provider, ok := m.ActiveAuthProvider(ctx)
	if !ok {
		return nil, auth.ErrNotAuthenticated
	}
	ai, err := provider.VerifyBearer(ctx, token)
	if err != nil {
		return nil, err
	}
	identity := provider.ToIdentity(ctx, ai)
	if identity.Username == "" {
		return nil, auth.ErrNotAuthenticated
	}
	return identity, nil
}

