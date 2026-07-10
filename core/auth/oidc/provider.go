package oidc

import (
	"context"
	"net/http"

	"github.com/navidrome/navidrome/core/auth"
)

type Claims struct {
	Subject           string   `json:"sub"`
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	Name              string   `json:"name"`
	Groups            []string `json:"groups"`
}

type OIDCIdentityProvider struct {
}

func New() *OIDCIdentityProvider {
	return &OIDCIdentityProvider{}
}

func (p *OIDCIdentityProvider) Name() string {
	return "oidc"
}

func (p *OIDCIdentityProvider) Authenticate(ctx context.Context, r *http.Request) (*auth.Identity, error) {
	return nil, auth.ErrNotAuthenticated
}
