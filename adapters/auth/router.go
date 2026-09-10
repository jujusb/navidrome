package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/url"
	"time"

	"github.com/deluan/rest"
	"github.com/go-chi/chi/v5"
	"github.com/navidrome/navidrome/conf"
	core "github.com/navidrome/navidrome/core/auth"
	"github.com/navidrome/navidrome/log"
	"github.com/navidrome/navidrome/model"
	"github.com/navidrome/navidrome/plugins"
	"github.com/navidrome/navidrome/server/events"
	"github.com/navidrome/navidrome/utils/req"
)

// Router serves the generic auth endpoints. All protocol-specific work is
// delegated to the single active auth provider plugin.
type Router struct {
	http.Handler
	ds      model.DataStore
	manager *plugins.Manager
}

func NewRouter(ds model.DataStore) *Router {
	r := &Router{
		ds:      ds,
		manager: plugins.GetManager(ds, events.GetBroker(), nil),
	}
	r.Handler = r.routes()
	return r
}

func (s *Router) routes() http.Handler {
	r := chi.NewRouter()

	r.Get("/login", s.login)
	r.Get("/callback", s.callback)
	r.Get("/status", s.status)
	r.Get("/logout", s.logout)

	return r
}

func (s *Router) activeProvider(ctx context.Context) (*plugins.AuthProviderPlugin, bool) {
	return s.manager.ActiveAuthProvider(ctx)
}

func defaultRedirectURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/api/auth/callback"
}

func (s *Router) redirectURL(r *http.Request) string {
	return defaultRedirectURL(r)
}

func generateState() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Router) login(w http.ResponseWriter, r *http.Request) {
	provider, ok := s.activeProvider(r.Context())
	if !ok {
		_ = rest.RespondWithError(w, http.StatusBadRequest, "No auth provider enabled")
		return
	}

	state := generateState()
	nonce := generateState()

	http.SetCookie(w, &http.Cookie{
		Name:     "auth_state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(10 * time.Minute / time.Second),
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "auth_nonce",
		Value:    nonce,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(10 * time.Minute / time.Second),
	})

	authURL, err := provider.GetLoginURL(r.Context(), state, nonce, s.redirectURL(r))
	if err != nil {
		log.Error(r.Context(), "Error generating auth URL", err)
		_ = rest.RespondWithError(w, http.StatusInternalServerError, "Failed to generate auth URL")
		return
	}

	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Router) callback(w http.ResponseWriter, r *http.Request) {
	provider, ok := s.activeProvider(r.Context())
	if !ok {
		_ = rest.RespondWithError(w, http.StatusBadRequest, "No auth provider enabled")
		return
	}

	p := req.Params(r)

	code, err := p.String("code")
	if err != nil {
		_ = rest.RespondWithError(w, http.StatusBadRequest, "authorization code not received")
		return
	}

	stateCookie, err := r.Cookie("auth_state")
	if err != nil {
		_ = rest.RespondWithError(w, http.StatusBadRequest, "missing state cookie")
		return
	}

	returnedState, err := p.String("state")
	if err != nil {
		_ = rest.RespondWithError(w, http.StatusBadRequest, "state not received")
		return
	}

	if stateCookie.Value != returnedState {
		_ = rest.RespondWithError(w, http.StatusBadRequest, "state mismatch")
		return
	}

	nonceCookie, err := r.Cookie("auth_nonce")
	if err != nil {
		nonceCookie = &http.Cookie{Value: ""}
	}

	ai, err := provider.ExchangeCode(r.Context(), code, returnedState, nonceCookie.Value, s.redirectURL(r))
	if err != nil {
		log.Error(r.Context(), "Error exchanging auth code for token", err)
		_ = rest.RespondWithError(w, http.StatusBadGateway, "Failed to exchange authorization code")
		return
	}

	identity := provider.ToIdentity(r.Context(), ai)

	svc := core.NewLoginService(s.ds)
	user, tokenString, err := svc.Login(r.Context(), identity)
	if err != nil {
		log.Error(r.Context(), "Error logging in with auth identity", err)
		_ = rest.RespondWithError(w, http.StatusInternalServerError, "Failed to login")
		return
	}

	if identity.IsAdmin != user.IsAdmin {
		user.IsAdmin = identity.IsAdmin
		if err := s.ds.User(r.Context()).Put(user); err != nil {
			log.Error(r.Context(), "Could not update admin status", "user", user.UserName, err)
		}
	}

	redirectURL := conf.Server.BaseURL + "/app/#/login?token=" + tokenString +
		"&userId=" + user.ID +
		"&username=" + user.UserName +
		"&name=" + user.Name +
		"&isAdmin=" + boolToString(user.IsAdmin) +
		"&idToken=" + url.QueryEscape(ai.IDToken)

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (s *Router) logout(w http.ResponseWriter, r *http.Request) {
	idTokenHint := r.URL.Query().Get("id_token")
	postLogoutRedirectURI := s.appURL(r) + "/#/login"

	provider, ok := s.activeProvider(r.Context())
	if !ok {
		http.Redirect(w, r, postLogoutRedirectURI, http.StatusFound)
		return
	}

	logoutURL, err := provider.GetLogoutURL(r.Context(), postLogoutRedirectURI, idTokenHint)
	if err != nil {
		log.Error(r.Context(), "Error generating logout URL", err)
		http.Redirect(w, r, postLogoutRedirectURI, http.StatusFound)
		return
	}

	log.Info(r.Context(), "Auth logout", "idTokenHint", idTokenHint != "", "logoutURL", logoutURL)
	if logoutURL == "" {
		http.Redirect(w, r, postLogoutRedirectURI, http.StatusFound)
		return
	}
	http.Redirect(w, r, logoutURL, http.StatusFound)
}

func (s *Router) appURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/app"
}

func (s *Router) status(w http.ResponseWriter, r *http.Request) {
	provider, ok := s.activeProvider(r.Context())
	if !ok {
		_ = rest.RespondWithJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}

	status, err := provider.GetStatus(r.Context(), s.appURL(r))
	if err != nil || !status.Enabled {
		_ = rest.RespondWithJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}

	resp := map[string]any{
		"enabled":      true,
		"providerId":   status.ProviderID,
		"buttonText":   status.ButtonText,
		"autoRedirect": status.AutoRedirect,
		"issuer":       status.Issuer,
		"clientId":     status.ClientID,
		"logoutUrl":    status.LogoutURL,
		"matchBy":      status.MatchBy,
	}
	_ = rest.RespondWithJSON(w, http.StatusOK, resp)
}

func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}