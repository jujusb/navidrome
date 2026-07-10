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
}

type IdentityProvider interface {
	Name() string
	Authenticate(ctx context.Context, r *http.Request) (*Identity, error)
}
