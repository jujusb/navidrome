package oidc

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
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

	return r
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

	authURL, err := s.provider.AuthCodeURL(state, nonce)
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

	rawIDToken, _, err := s.provider.Exchange(r.Context(), code)
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
		isAdmin := false
		if claimVal := getClaimFromToken(claims, o.AdminClaim); claimVal == o.AdminValue {
			isAdmin = true
		}
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
		"&isAdmin=" + boolToString(user.IsAdmin)

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (s *Router) status(w http.ResponseWriter, r *http.Request) {
	o := conf.Server.OIDC
	resp := map[string]any{
		"enabled":       o.Enabled,
		"issuer":        o.Issuer,
		"clientId":      o.ClientID,
		"redirectUrl":   o.RedirectURL,
		"autoProvision": o.AutoProvision,
		"adminClaim":    o.AdminClaim,
		"adminValue":    o.AdminValue,
		"groupsClaim":   o.GroupsClaim,
	}
	_ = rest.RespondWithJSON(w, http.StatusOK, resp)
}

func getClaimFromToken(claims *oidc.Claims, claim string) string {
	switch claim {
	case "sub":
		return claims.Subject
	case "preferred_username":
		return claims.PreferredUsername
	case "email":
		return claims.Email
	case "name":
		return claims.Name
	default:
		return ""
	}
}

func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
