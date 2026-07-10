package password

import (
	"context"
	"errors"
	"net/http"

	"github.com/navidrome/navidrome/core/auth"
	"github.com/navidrome/navidrome/model"
)

type PasswordIdentityProvider struct {
	userRepo model.UserRepository
}

func New(userRepo model.UserRepository) *PasswordIdentityProvider {
	return &PasswordIdentityProvider{userRepo: userRepo}
}

func (p *PasswordIdentityProvider) Name() string {
	return "password"
}

func (p *PasswordIdentityProvider) Authenticate(ctx context.Context, r *http.Request) (*auth.Identity, error) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	return p.AuthenticateCredentials(ctx, username, password)
}

func (p *PasswordIdentityProvider) AuthenticateCredentials(ctx context.Context, username, password string) (*auth.Identity, error) {
	if username == "" || password == "" {
		return nil, auth.ErrInvalidCredentials
	}

	user, err := p.userRepo.FindByUsernameWithPassword(username)
	if errors.Is(err, model.ErrNotFound) {
		return nil, auth.ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	if user.Password != password {
		return nil, auth.ErrInvalidCredentials
	}

	return &auth.Identity{
		Provider:    p.Name(),
		Subject:     user.ID,
		Username:    user.UserName,
		Email:       user.Email,
		DisplayName: user.Name,
	}, nil
}
