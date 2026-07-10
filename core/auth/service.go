package auth

import (
	"context"
	"errors"
	"time"

	"github.com/navidrome/navidrome/consts"
	"github.com/navidrome/navidrome/log"
	"github.com/navidrome/navidrome/model"
	"github.com/navidrome/navidrome/model/id"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type LoginService struct {
	ds model.DataStore
}

func NewLoginService(ds model.DataStore) *LoginService {
	return &LoginService{ds: ds}
}

func (s *LoginService) Login(ctx context.Context, identity *Identity) (*model.User, string, error) {
	user, err := s.resolve(ctx, identity)
	if err != nil {
		return nil, "", err
	}

	token, err := CreateToken(user)
	if err != nil {
		return nil, "", err
	}

	return user, token, nil
}

func (s *LoginService) Provision(ctx context.Context, identity *Identity) (*model.User, error) {
	return s.resolve(ctx, identity)
}

func (s *LoginService) resolve(ctx context.Context, identity *Identity) (*model.User, error) {
	userRepo := s.ds.User(ctx)

	user, err := userRepo.FindByUsername(identity.Username)
	if errors.Is(err, model.ErrNotFound) {
		user, err = s.createUser(ctx, identity)
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}

	s.syncUser(ctx, user, identity)

	err = userRepo.UpdateLastLoginAt(user.ID)
	if err != nil {
		log.Error(ctx, "Could not update LastLoginAt", "user", identity.Username, err)
	}

	return user, nil
}

func (s *LoginService) createUser(ctx context.Context, identity *Identity) (*model.User, error) {
	userRepo := s.ds.User(ctx)

	count, _ := userRepo.CountAll()
	isFirstUser := count == 0

	caser := cases.Title(language.Und)
	if identity.DisplayName == "" {
		identity.DisplayName = caser.String(identity.Username)
	}

	now := time.Now()
	user := &model.User{
		ID:          id.NewRandom(),
		UserName:    identity.Username,
		Name:        identity.DisplayName,
		Email:       identity.Email,
		NewPassword: consts.PasswordAutogenPrefix + id.NewRandom(),
		IsAdmin:     isFirstUser,
		LastLoginAt: &now,
	}

	err := userRepo.Put(user)
	if err != nil {
		log.Error(ctx, "Could not create user", "user", identity.Username, err)
		return nil, err
	}

	log.Info(ctx, "Created new user", "username", identity.Username, "fromProvider", identity.Provider, "isAdmin", isFirstUser)
	return user, nil
}

func (s *LoginService) syncUser(ctx context.Context, user *model.User, identity *Identity) {
	updated := false

	if identity.DisplayName != "" && user.Name != identity.DisplayName {
		user.Name = identity.DisplayName
		updated = true
	}
	if identity.Email != "" && user.Email != identity.Email {
		user.Email = identity.Email
		updated = true
	}

	if updated {
		err := s.ds.User(ctx).Put(user)
		if err != nil {
			log.Error(ctx, "Could not update user profile", "user", identity.Username, err)
		}
	}
}
