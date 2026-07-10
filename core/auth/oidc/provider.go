package oidc

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/navidrome/navidrome/conf"
	"github.com/navidrome/navidrome/core/auth"
)

type Claims struct {
	Subject           string   `json:"sub"`
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"email_verified"`
	Name              string   `json:"name"`
	Groups            []string `json:"groups"`
	Roles             []string `json:"roles"`
	All               map[string]any
}

type oidcConfig struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSUri               string `json:"jwks_uri"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Use string `json:"use"`
}

type idToken struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience any    `json:"aud"`
	Expiry   int64  `json:"exp"`
	IssuedAt int64  `json:"iat"`
	Nonce    string `json:"nonce"`
}

type OIDCIdentityProvider struct {
	mu     sync.RWMutex
	config *oidcConfig
	jwks   *jwks
	client *http.Client
}

func New() *OIDCIdentityProvider {
	return &OIDCIdentityProvider{
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (p *OIDCIdentityProvider) Name() string {
	return "oidc"
}

func (p *OIDCIdentityProvider) Authenticate(ctx context.Context, r *http.Request) (*auth.Identity, error) {
	return nil, auth.ErrNotAuthenticated
}

func (p *OIDCIdentityProvider) Enabled() bool {
	o := conf.Server.OIDC
	return o.Enabled && o.Issuer != "" && o.ClientID != ""
}

func (p *OIDCIdentityProvider) AuthCodeURL(state, nonce, redirectURL string) (string, error) {
	cfg, err := p.getConfig()
	if err != nil {
		return "", err
	}

	o := conf.Server.OIDC
	scopes := strings.Join(o.Scopes, "+")

	u := fmt.Sprintf("%s?client_id=%s&response_type=code&scope=%s&redirect_uri=%s&state=%s&nonce=%s",
		cfg.AuthorizationEndpoint,
		url.QueryEscape(o.ClientID),
		scopes,
		url.QueryEscape(redirectURL),
		url.QueryEscape(state),
		url.QueryEscape(nonce),
	)
	return u, nil
}

func (p *OIDCIdentityProvider) LogoutURL(postLogoutRedirectURI, idTokenHint string) string {
	cfg, err := p.getConfig()
	if err != nil || cfg.EndSessionEndpoint == "" {
		return ""
	}
	u := cfg.EndSessionEndpoint + "?post_logout_redirect_uri=" + url.QueryEscape(postLogoutRedirectURI)
	if idTokenHint != "" {
		u += "&id_token_hint=" + url.QueryEscape(idTokenHint)
	}
	return u
}

func (p *OIDCIdentityProvider) Exchange(ctx context.Context, code, redirectURL string) (idToken string, accessToken string, err error) {
	cfg, err := p.getConfig()
	if err != nil {
		return "", "", err
	}

	o := conf.Server.OIDC

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURL)
	data.Set("client_id", o.ClientID)
	data.Set("client_secret", o.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return "", "", fmt.Errorf("oidc: creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("oidc: token request: %w", err)
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", "", fmt.Errorf("oidc: decoding token response: %w", err)
	}

	if tokenResp.Error != "" {
		return "", "", fmt.Errorf("oidc: token error: %s - %s", tokenResp.Error, tokenResp.ErrorDesc)
	}

	return tokenResp.IDToken, tokenResp.AccessToken, nil
}

func (p *OIDCIdentityProvider) VerifyIDToken(ctx context.Context, rawIDToken string, nonce string) (*Claims, error) {
	parts := strings.Split(rawIDToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("oidc: invalid JWT format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("oidc: decoding header: %w", err)
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("oidc: parsing header: %w", err)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oidc: decoding payload: %w", err)
	}

	var token idToken
	if err := json.Unmarshal(payloadBytes, &token); err != nil {
		return nil, fmt.Errorf("oidc: parsing payload: %w", err)
	}

	o := conf.Server.OIDC
	cfg, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	if token.Issuer != cfg.Issuer {
		return nil, fmt.Errorf("oidc: token issuer mismatch")
	}

	switch aud := token.Audience.(type) {
	case string:
		if aud != o.ClientID {
			return nil, fmt.Errorf("oidc: token audience mismatch")
		}
	case []string:
		valid := false
		for _, a := range aud {
			if a == o.ClientID {
				valid = true
				break
			}
		}
		if !valid {
			return nil, fmt.Errorf("oidc: token audience mismatch")
		}
	default:
		return nil, fmt.Errorf("oidc: unexpected audience type")
	}

	if time.Now().Unix() > token.Expiry {
		return nil, fmt.Errorf("oidc: token expired")
	}

	if nonce != "" && token.Nonce != nonce {
		return nil, fmt.Errorf("oidc: nonce mismatch")
	}

	if err := p.verifySignature(rawIDToken, header.Kid); err != nil {
		return nil, fmt.Errorf("oidc: signature verification: %w", err)
	}

	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("oidc: parsing claims: %w", err)
	}

	var rawClaims map[string]any
	if err := json.Unmarshal(payloadBytes, &rawClaims); err == nil {
		claims.All = rawClaims
	}

	return &claims, nil
}

func (p *OIDCIdentityProvider) verifySignature(rawJWT string, kid string) error {
	keys, err := p.getJWKS()
	if err != nil {
		return err
	}

	var key *jwk
	for _, k := range keys.Keys {
		if k.Kid == kid || (kid == "" && k.Use == "sig") {
			key = &k
			break
		}
	}
	if key == nil {
		return fmt.Errorf("key not found: %s", kid)
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return fmt.Errorf("decoding modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return fmt.Errorf("decoding exponent: %w", err)
	}

	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}

	parts := strings.Split(rawJWT, ".")
	signingInput := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("decoding signature: %w", err)
	}

	hash := sha256.Sum256([]byte(signingInput))
	return rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], signature)
}

func (p *OIDCIdentityProvider) GetUserInfo(ctx context.Context, accessToken string) (*Claims, error) {
	cfg, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.UserinfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc: creating userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: userinfo request: %w", err)
	}
	defer resp.Body.Close()

	var claims Claims
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return nil, fmt.Errorf("oidc: decoding userinfo: %w", err)
	}

	return &claims, nil
}

func (p *OIDCIdentityProvider) getConfig() (*oidcConfig, error) {
	p.mu.RLock()
	cached := p.config
	p.mu.RUnlock()
	if cached != nil {
		return cached, nil
	}

	return p.fetchConfig()
}

func (p *OIDCIdentityProvider) fetchConfig() (*oidcConfig, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.config != nil {
		return p.config, nil
	}

	o := conf.Server.OIDC
	discURL := strings.TrimRight(o.Issuer, "/") + "/.well-known/openid-configuration"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discURL, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc: creating discovery request: %w", err)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery request: %w", err)
	}
	defer resp.Body.Close()

	var cfg oidcConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("oidc: decoding discovery: %w", err)
	}

	p.config = &cfg
	return p.config, nil
}

func (p *OIDCIdentityProvider) getJWKS() (*jwks, error) {
	cfg, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	p.mu.RLock()
	cached := p.jwks
	p.mu.RUnlock()
	if cached != nil {
		return cached, nil
	}

	return p.fetchJWKS(cfg)
}

func (p *OIDCIdentityProvider) fetchJWKS(cfg *oidcConfig) (*jwks, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.jwks != nil {
		return p.jwks, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.JWKSUri, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc: creating JWKS request: %w", err)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: JWKS request: %w", err)
	}
	defer resp.Body.Close()

	var keys jwks
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return nil, fmt.Errorf("oidc: decoding JWKS: %w", err)
	}

	p.jwks = &keys
	return p.jwks, nil
}

func (p *OIDCIdentityProvider) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = nil
	p.jwks = nil
}
