package oidc

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/url"
	"time"

	"github.com/deluan/rest"
	"github.com/go-chi/chi/v5"
	"github.com/navidrome/navidrome/conf"
	"github.com/navidrome/navidrome/core/auth"
	oidc "github.com/navidrome/navidrome/core/auth/oidc"
	"github.com/navidrome/navidrome/log"
	"github.com/navidrome/navidrome/model"
	"github.com/navidrome/navidrome/utils/req"
)

type Router struct {
	http.Handler
	ds       model.DataStore
	provider *oidc.OIDCIdentityProvider
}

func NewRouter(ds model.DataStore) *Router {
	r := &Router{
		ds:       ds,
		provider: oidc.New(),
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

func (s *Router) ResetOIDCProvider() {
	s.provider.Reset()
}

func defaultRedirectURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/api/oauth/callback"
}

func (s *Router) redirectURL(r *http.Request) string {
	if conf.Server.OIDC.RedirectURL != "" {
		return conf.Server.OIDC.RedirectURL
	}
	return defaultRedirectURL(r)
}

func generateState() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Router) login(w http.ResponseWriter, r *http.Request) {
	if !s.provider.Enabled() {
		_ = rest.RespondWithError(w, http.StatusBadRequest, "OIDC is not enabled")
		return
	}

	state := generateState()
	nonce := generateState()

	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(10 * time.Minute / time.Second),
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_nonce",
		Value:    nonce,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(10 * time.Minute / time.Second),
	})

	authURL, err := s.provider.AuthCodeURL(state, nonce, s.redirectURL(r))
	if err != nil {
		log.Error(r.Context(), "Error generating OIDC auth URL", err)
		_ = rest.RespondWithError(w, http.StatusInternalServerError, "Failed to generate auth URL")
		return
	}

	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Router) callback(w http.ResponseWriter, r *http.Request) {
	p := req.Params(r)

	code, err := p.String("code")
	if err != nil {
		_ = rest.RespondWithError(w, http.StatusBadRequest, "authorization code not received")
		return
	}

	stateCookie, err := r.Cookie("oidc_state")
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

	nonceCookie, err := r.Cookie("oidc_nonce")
	if err != nil {
		nonceCookie = &http.Cookie{Value: ""}
	}

	rawIDToken, _, err := s.provider.Exchange(r.Context(), code, s.redirectURL(r))
	if err != nil {
		log.Error(r.Context(), "Error exchanging OIDC code for token", err)
		_ = rest.RespondWithError(w, http.StatusBadGateway, "Failed to exchange authorization code")
		return
	}

	claims, err := s.provider.VerifyIDToken(r.Context(), rawIDToken, nonceCookie.Value)
	if err != nil {
		log.Error(r.Context(), "Error verifying OIDC ID token", err)
		_ = rest.RespondWithError(w, http.StatusBadGateway, "Failed to verify ID token")
		return
	}

	username := claims.PreferredUsername
	if username == "" {
		username = claims.Email
	}
	if username == "" {
		username = claims.Subject
	}

	identity := &auth.Identity{
		Provider:    "oidc",
		Subject:     claims.Subject,
		Username:    username,
		DisplayName: claims.Name,
		Email:       claims.Email,
	}

	svc := auth.NewLoginService(s.ds)
	user, tokenString, err := svc.Login(r.Context(), identity)
	if err != nil {
		log.Error(r.Context(), "Error logging in with OIDC identity", err)
		_ = rest.RespondWithError(w, http.StatusInternalServerError, "Failed to login")
		return
	}

	o := conf.Server.OIDC
	if o.AdminClaim != "" && o.AdminValue != "" {
		isAdmin := containsAdminClaim(claims, o.AdminClaim, o.AdminValue)
		if user.IsAdmin != isAdmin {
			user.IsAdmin = isAdmin
			if err := s.ds.User(r.Context()).Put(user); err != nil {
				log.Error(r.Context(), "Could not update admin status", "user", user.UserName, err)
			}
		}
	}

	redirectURL := conf.Server.BaseURL + "/app/#/login?token=" + tokenString +
		"&userId=" + user.ID +
		"&username=" + user.UserName +
		"&name=" + user.Name +
		"&isAdmin=" + boolToString(user.IsAdmin) +
		"&idToken=" + url.QueryEscape(rawIDToken)

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (s *Router) logout(w http.ResponseWriter, r *http.Request) {
	idTokenHint := r.URL.Query().Get("id_token")
	postLogoutRedirectURI := conf.Server.BaseURL + "/app"
	logoutURL := s.provider.LogoutURL(postLogoutRedirectURI, idTokenHint)
	if logoutURL == "" {
		http.Redirect(w, r, postLogoutRedirectURI, http.StatusFound)
		return
	}
	http.Redirect(w, r, logoutURL, http.StatusFound)
}

func (s *Router) status(w http.ResponseWriter, r *http.Request) {
	o := conf.Server.OIDC
	resp := map[string]any{
		"enabled":       o.Enabled,
		"issuer":        o.Issuer,
		"clientId":      o.ClientID,
		"redirectUrl":   o.RedirectURL,
		"autoProvision": o.AutoProvision,
		"autoRedirect":  o.AutoRedirect,
		"adminClaim":    o.AdminClaim,
		"adminValue":    o.AdminValue,
		"groupsClaim":   o.GroupsClaim,
		"logoutUrl":     s.provider.LogoutURL(conf.Server.BaseURL+"/app", ""),
	}
	_ = rest.RespondWithJSON(w, http.StatusOK, resp)
}

func getClaimFromToken(claims *oidc.Claims, claim string) string {
	// First check raw claims map (covers any custom claim)
	if claims.All != nil {
		if val, ok := claims.All[claim]; ok {
			switch v := val.(type) {
			case string:
				return v
			case []any:
				if len(v) > 0 {
					if s, ok := v[0].(string); ok {
						return s
					}
				}
			}
		}
	}
	return ""
}

func containsAdminClaim(claims *oidc.Claims, claim, value string) bool {
	if claims.All != nil {
		if val, ok := claims.All[claim]; ok {
			switch v := val.(type) {
			case string:
				return v == value
			case []any:
				for _, item := range v {
					if s, ok := item.(string); ok && s == value {
						return true
					}
				}
			}
		}
	}
	return false
}

func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
