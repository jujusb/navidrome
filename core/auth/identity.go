package auth

import (
	"context"
	"errors"
	"net/http"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrNotAuthenticated   = errors.New("request not authenticated")
)

type Identity struct {
	Provider    string
	Subject     string
	Username    string
	Email       string
	DisplayName string
	Groups      []string
	Claims      map[string]any
	// IsAdmin indicates the provider wants this user to be granted admin
	// rights. Only set by auth provider plugins.
	IsAdmin bool
	// IDToken is the raw ID token returned by an auth provider plugin,
	// used as an id_token_hint during single sign-out.
	IDToken string
}

type IdentityProvider interface {
	Name() string
	Authenticate(ctx context.Context, r *http.Request) (*Identity, error)
}
