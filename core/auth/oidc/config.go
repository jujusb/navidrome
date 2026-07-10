package oidc

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/navidrome/navidrome/conf"
	"github.com/navidrome/navidrome/model"
)

const oidcConfigPropertyKey = "oidc_config"

type Config struct {
	Enabled             bool     `json:"enabled"`
	Issuer              string   `json:"issuer"`
	ClientID            string   `json:"clientId"`
	ClientSecret        string   `json:"clientSecret"`
	RedirectURL         string   `json:"redirectUrl"`
	Scopes              []string `json:"scopes"`
	AutoProvision       bool     `json:"autoProvision"`
	AutoRedirect        bool     `json:"autoRedirect"`
	AdminClaim          string   `json:"adminClaim"`
	AdminValue          string   `json:"adminValue"`
	GroupsClaim         string   `json:"groupsClaim"`
	SigningAlgorithm    string   `json:"signingAlgorithm"`
	AllowedRedirectURIs []string `json:"allowedRedirectURIs"`
	ButtonText          string   `json:"buttonText"`
	MatchBy             string   `json:"matchBy"`
}

// Load reads the current OIDC configuration, merging config file values with DB overrides.
func Load() Config {
	cfg := Config{
		Enabled:             conf.Server.OIDC.Enabled,
		Issuer:              conf.Server.OIDC.Issuer,
		ClientID:            conf.Server.OIDC.ClientID,
		ClientSecret:        conf.Server.OIDC.ClientSecret,
		RedirectURL:         conf.Server.OIDC.RedirectURL,
		Scopes:              conf.Server.OIDC.Scopes,
		AutoProvision:       conf.Server.OIDC.AutoProvision,
		AutoRedirect:        conf.Server.OIDC.AutoRedirect,
		AdminClaim:          conf.Server.OIDC.AdminClaim,
		AdminValue:          conf.Server.OIDC.AdminValue,
		GroupsClaim:         conf.Server.OIDC.GroupsClaim,
		SigningAlgorithm:    conf.Server.OIDC.SigningAlgorithm,
		AllowedRedirectURIs: conf.Server.OIDC.AllowedRedirectURIs,
		ButtonText:          conf.Server.OIDC.ButtonText,
		MatchBy:             conf.Server.OIDC.MatchBy,
	}
	return cfg
}

// LoadFromDB reads the OIDC config from the database, merging with config file values.
func LoadFromDB(ctx context.Context, ds model.DataStore) (Config, error) {
	cfg := Load()

	val, err := ds.Property(ctx).DefaultGet(oidcConfigPropertyKey, "")
	if err != nil {
		return cfg, fmt.Errorf("reading OIDC config from DB: %w", err)
	}
	if val == "" {
		return cfg, nil
	}

	var dbCfg Config
	if err := json.Unmarshal([]byte(val), &dbCfg); err != nil {
		return cfg, fmt.Errorf("parsing OIDC config from DB: %w", err)
	}

	if dbCfg.Issuer != "" {
		cfg.Issuer = dbCfg.Issuer
	}
	if dbCfg.ClientID != "" {
		cfg.ClientID = dbCfg.ClientID
	}
	if dbCfg.ClientSecret != "" {
		cfg.ClientSecret = dbCfg.ClientSecret
	}
	if dbCfg.RedirectURL != "" {
		cfg.RedirectURL = dbCfg.RedirectURL
	}
	if dbCfg.Scopes != nil {
		cfg.Scopes = dbCfg.Scopes
	}
	if dbCfg.AdminClaim != "" {
		cfg.AdminClaim = dbCfg.AdminClaim
	}
	if dbCfg.AdminValue != "" {
		cfg.AdminValue = dbCfg.AdminValue
	}
	if dbCfg.GroupsClaim != "" {
		cfg.GroupsClaim = dbCfg.GroupsClaim
	}
	if dbCfg.SigningAlgorithm != "" {
		cfg.SigningAlgorithm = dbCfg.SigningAlgorithm
	}
	if dbCfg.AllowedRedirectURIs != nil {
		cfg.AllowedRedirectURIs = dbCfg.AllowedRedirectURIs
	}
	if dbCfg.ButtonText != "" {
		cfg.ButtonText = dbCfg.ButtonText
	}
	if dbCfg.MatchBy != "" {
		cfg.MatchBy = dbCfg.MatchBy
	}
	cfg.Enabled = dbCfg.Enabled
	cfg.AutoProvision = dbCfg.AutoProvision
	cfg.AutoRedirect = dbCfg.AutoRedirect

	return cfg, nil
}

// Save persists the OIDC configuration to the database.
func Save(ctx context.Context, ds model.DataStore, cfg Config) error {
	data, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshaling OIDC config: %w", err)
	}
	if err := ds.Property(ctx).Put(oidcConfigPropertyKey, string(data)); err != nil {
		return fmt.Errorf("saving OIDC config: %w", err)
	}
	return nil
}
