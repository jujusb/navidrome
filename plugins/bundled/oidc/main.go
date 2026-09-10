// OIDC (OpenID Connect) auth provider plugin for Navidrome.
//
// This plugin implements the auth_provider capability and implements the full
// OIDC Authorization Code flow: it performs provider discovery, fetches the
// JWKS, exchanges authorization codes for tokens, verifies the ID token
// signature and extracts the identity claims. Navidrome (the host) is
// responsible for HTTP routing, CSRF state cookies, user provisioning and JWT
// session creation.
//
// Build with:
//
//	tinygo build -o ../../../oidc.wasm -target wasip1 -buildmode=c-shared .
//
// Package into a .ndp:
//
//	cp ../../../oidc.wasm plugin.wasm && zip -j oidc.ndp manifest.json plugin.wasm && rm plugin.wasm
//
// Install by copying oidc.ndp to your Navidrome plugins folder.
package main

import (
	"crypto"
	"crypto/rsa"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/navidrome/navidrome/plugins/pdk/go/authprovider"
	"github.com/navidrome/navidrome/plugins/pdk/go/host"
	"github.com/navidrome/navidrome/plugins/pdk/go/pdk"
)

// oidcPlugin implements the authprovider.AuthProvider interface using OpenID Connect.
type oidcPlugin struct{}

// init registers the plugin implementation
func init() {
	authprovider.Register(&oidcPlugin{})
}

// Ensure oidcPlugin implements the AuthProvider interface
var _ authprovider.AuthProvider = (*oidcPlugin)(nil)

// settings holds the runtime configuration read from the Navidrome config.
type settings struct {
	issuer       string
	clientID     string
	clientSecret string
	scopes       []string
	matchBy      string
	adminClaim   string
	adminValue   string
	autoRedirect bool
	buttonText   string
}

func (s *settings) enabled() bool {
	return s.issuer != "" && s.clientID != ""
}

func readConfig() *settings {
	s := &settings{
		scopes:     []string{"openid", "profile", "email"},
		matchBy:    "preferred_username",
		buttonText: "Login with SSO",
	}
	if v, ok := host.ConfigGet("issuer"); ok {
		s.issuer = v
	}
	if v, ok := host.ConfigGet("clientId"); ok {
		s.clientID = v
	}
	if v, ok := host.ConfigGet("clientSecret"); ok {
		s.clientSecret = v
	}
	if v, ok := host.ConfigGet("scopes"); ok && v != "" {
		var scopes []string
		if err := json.Unmarshal([]byte(v), &scopes); err == nil && len(scopes) > 0 {
			s.scopes = scopes
		}
	}
	if v, ok := host.ConfigGet("matchBy"); ok && v != "" {
		s.matchBy = v
	}
	if v, ok := host.ConfigGet("adminClaim"); ok {
		s.adminClaim = v
	}
	if v, ok := host.ConfigGet("adminValue"); ok {
		s.adminValue = v
	}
	if v, ok := host.ConfigGet("autoRedirect"); ok {
		s.autoRedirect = v == "true"
	}
	if v, ok := host.ConfigGet("buttonText"); ok && v != "" {
		s.buttonText = v
	}
	return s
}

// oidcConfig is the OpenID Provider configuration document (discovery).
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

type claims struct {
	Subject           string   `json:"sub"`
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"email_verified"`
	Name              string   `json:"name"`
	Groups            []string `json:"groups"`
	Roles             []string `json:"roles"`
	All               map[string]any
}

// doRequest executes an HTTP request through the Navidrome host and returns the
// response body for non-error status codes.
func doRequest(method, reqURL string, headers map[string]string, body []byte) (*host.HTTPResponse, error) {
	pdk.Log(pdk.LogDebug, fmt.Sprintf("OIDC %s %s", method, reqURL))

	resp, err := host.HTTPSend(host.HTTPRequest{
		Method:    method,
		URL:       reqURL,
		Headers:   headers,
		Body:      body,
		TimeoutMs: 10000,
	})
	if err != nil {
		return nil, fmt.Errorf("oidc: %s request to %s: %w", method, reqURL, err)
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("oidc: %s request to %s returned status %d", method, reqURL, resp.StatusCode)
	}
	return resp, nil
}

// getCache retrieves a value from the plugin KV store.
func getCache(key string) ([]byte, bool, error) {
	return host.KVStoreGet(key)
}

// setCache stores a value in the plugin KV store with a TTL.
func setCache(key string, value []byte, ttlSeconds int64) error {
	return host.KVStoreSetWithTTL(key, value, ttlSeconds)
}

// discovery fetches (and caches) the OpenID Provider configuration document.
func discovery(s *settings) (*oidcConfig, error) {
	if cached, ok, err := getCache("oidc.discovery"); err == nil && ok {
		var cfg oidcConfig
		if err := json.Unmarshal(cached, &cfg); err == nil {
			return &cfg, nil
		}
	}

	discURL := strings.TrimRight(s.issuer, "/") + "/.well-known/openid-configuration"
	resp, err := doRequest("GET", discURL, map[string]string{"Accept": "application/json"}, nil)
	if err != nil {
		return nil, err
	}

	var cfg oidcConfig
	if err := json.Unmarshal(resp.Body, &cfg); err != nil {
		return nil, fmt.Errorf("oidc: decoding discovery document: %w", err)
	}
	if cfg.AuthorizationEndpoint == "" || cfg.TokenEndpoint == "" {
		return nil, errors.New("oidc: discovery document is missing required endpoints")
	}

	_ = setCache("oidc.discovery", resp.Body, 3600)
	return &cfg, nil
}

// getJWKS fetches (and caches) the JSON Web Key Set used to verify ID tokens.
func getJWKS() (*jwks, error) {
	s := readConfig()
	cfg, err := discovery(s)
	if err != nil {
		return nil, err
	}

	if cached, ok, err := getCache("oidc.jwks"); err == nil && ok {
		var keys jwks
		if err := json.Unmarshal(cached, &keys); err == nil {
			return &keys, nil
		}
	}

	resp, err := doRequest("GET", cfg.JWKSUri, map[string]string{"Accept": "application/json"}, nil)
	if err != nil {
		return nil, err
	}

	var keys jwks
	if err := json.Unmarshal(resp.Body, &keys); err != nil {
		return nil, fmt.Errorf("oidc: decoding JWKS: %w", err)
	}

	_ = setCache("oidc.jwks", resp.Body, 3600)
	return &keys, nil
}

// verifyIDToken validates a raw JWT ID token and extracts its claims.
func verifyIDToken(s *settings, cfg *oidcConfig, rawIDToken, nonce string) (*claims, error) {
	parts := strings.Split(rawIDToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("oidc: invalid JWT format")
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

	if token.Issuer != cfg.Issuer {
		return nil, errors.New("oidc: token issuer mismatch")
	}

	switch aud := token.Audience.(type) {
	case string:
		if aud != s.clientID {
			return nil, errors.New("oidc: token audience mismatch")
		}
	case []any:
		if !stringSliceContains(aud, s.clientID) {
			return nil, errors.New("oidc: token audience mismatch")
		}
	default:
		return nil, errors.New("oidc: unexpected audience type")
	}

	if time.Now().Unix() > token.Expiry {
		return nil, errors.New("oidc: token expired")
	}

	if nonce != "" && token.Nonce != nonce {
		return nil, errors.New("oidc: nonce mismatch")
	}

	if err := verifySignature(rawIDToken, header.Kid); err != nil {
		return nil, fmt.Errorf("oidc: signature verification: %w", err)
	}

	var c claims
	if err := json.Unmarshal(payloadBytes, &c); err != nil {
		return nil, fmt.Errorf("oidc: parsing claims: %w", err)
	}

	var rawClaims map[string]any
	if err := json.Unmarshal(payloadBytes, &rawClaims); err == nil {
		c.All = rawClaims
	}

	return &c, nil
}

func stringSliceContains(slice []any, value string) bool {
	for _, item := range slice {
		if s, ok := item.(string); ok && s == value {
			return true
		}
	}
	return false
}

func verifySignature(rawJWT string, kid string) error {
	keys, err := getJWKS()
	if err != nil {
		return err
	}

	var key *jwk
	for i := range keys.Keys {
		if keys.Keys[i].Kid == kid || (kid == "" && keys.Keys[i].Use == "sig") {
			key = &keys.Keys[i]
			break
		}
	}
	if key == nil {
		return fmt.Errorf("key not found: %s", kid)
	}

	parts := strings.Split(rawJWT, ".")
	signingInput := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("decoding signature: %w", err)
	}

	switch key.Kty {
	case "RSA":
		return verifyRSA(key, signingInput, signature)
	default:
		return fmt.Errorf("unsupported key type: %s (only RSA is supported)", key.Kty)
	}
}

func verifyRSA(key *jwk, signingInput string, signature []byte) error {
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

	var hash crypto.Hash
	switch key.Alg {
	case "RS384":
		hash = crypto.SHA384
	case "RS512":
		hash = crypto.SHA512
	default:
		hash = crypto.SHA256
	}

	h := hash.New()
	h.Write([]byte(signingInput))
	return rsa.VerifyPKCS1v15(pubKey, hash, h.Sum(nil), signature)
}

// buildIdentity converts verified claims into an authprovider.AuthIdentity.
func buildIdentity(s *settings, c *claims, idToken string) authprovider.AuthIdentity {
	username := ""
	switch s.matchBy {
	case "email":
		username = c.Email
	case "subject":
		username = c.Subject
	default:
		username = c.PreferredUsername
		if username == "" {
			username = c.Email
		}
		if username == "" {
			username = c.Subject
		}
	}

	ai := authprovider.AuthIdentity{
		Provider:    "oidc",
		Subject:     c.Subject,
		Username:    username,
		Email:       c.Email,
		DisplayName: c.Name,
		Groups:      c.Groups,
		Claims:      c.All,
		IDToken:     idToken,
	}

	if s.adminClaim != "" && s.adminValue != "" {
		ai.IsAdmin = containsClaimValue(c.All, s.adminClaim, s.adminValue)
	}

	return ai
}

// containsClaimValue checks whether a raw claim matches the expected value.
func containsClaimValue(all map[string]any, claim, value string) bool {
	if all == nil {
		return false
	}
	v, ok := all[claim]
	if !ok {
		return false
	}
	switch val := v.(type) {
	case string:
		return val == value
	case []any:
		for _, item := range val {
			if s, ok := item.(string); ok && s == value {
				return true
			}
		}
	case []string:
		for _, s := range val {
			if s == value {
				return true
			}
		}
	}
	return false
}

// buildLogoutURL builds the single sign-out URL from the discovery document.
func buildLogoutURL(cfg *oidcConfig, postLogoutRedirectURI, idTokenHint string) string {
	if cfg.EndSessionEndpoint == "" {
		return ""
	}
	u := cfg.EndSessionEndpoint + "?post_logout_redirect_uri=" + url.QueryEscape(postLogoutRedirectURI)
	if idTokenHint != "" {
		u += "&id_token_hint=" + url.QueryEscape(idTokenHint)
	}
	return u
}

// GetStatus returns the current status and public configuration.
func (*oidcPlugin) GetStatus(req authprovider.GetStatusRequest) (authprovider.AuthStatus, error) {
	s := readConfig()
	if !s.enabled() {
		return authprovider.AuthStatus{Enabled: false}, nil
	}

	logoutURL := ""
	cfg, err := discovery(s)
	if err == nil {
		logoutURL = buildLogoutURL(cfg, req.AppURL+"/#/login", "")
	} else {
		pdk.Log(pdk.LogWarn, "OIDC GetStatus: discovery failed: "+err.Error())
	}

	return authprovider.AuthStatus{
		Enabled:      true,
		ProviderID:   "oidc",
		ButtonText:   s.buttonText,
		AutoRedirect: s.autoRedirect,
		Issuer:       s.issuer,
		ClientID:     s.clientID,
		Scopes:       s.scopes,
		LogoutURL:    logoutURL,
		MatchBy:      s.matchBy,
	}, nil
}

// GetLoginURL generates the authorization URL to start a login.
func (*oidcPlugin) GetLoginURL(req authprovider.GetLoginURLRequest) (authprovider.GetLoginURLResponse, error) {
	s := readConfig()
	if !s.enabled() {
		return authprovider.GetLoginURLResponse{}, errors.New("oidc: provider is not enabled")
	}

	cfg, err := discovery(s)
	if err != nil {
		return authprovider.GetLoginURLResponse{}, err
	}

	scopes := strings.Join(s.scopes, "+")
	u := fmt.Sprintf("%s?client_id=%s&response_type=code&scope=%s&redirect_uri=%s&state=%s&nonce=%s",
		cfg.AuthorizationEndpoint,
		url.QueryEscape(s.clientID),
		scopes,
		url.QueryEscape(req.RedirectURI),
		url.QueryEscape(req.State),
		url.QueryEscape(req.Nonce),
	)
	return authprovider.GetLoginURLResponse{AuthorizationURL: u}, nil
}

// ExchangeCode trades an authorization code for an authenticated identity.
func (*oidcPlugin) ExchangeCode(req authprovider.ExchangeCodeRequest) (authprovider.AuthIdentity, error) {
	s := readConfig()
	if !s.enabled() {
		return authprovider.AuthIdentity{}, errors.New("oidc: provider is not enabled")
	}

	cfg, err := discovery(s)
	if err != nil {
		return authprovider.AuthIdentity{}, err
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", req.Code)
	data.Set("redirect_uri", req.RedirectURI)
	data.Set("client_id", s.clientID)
	data.Set("client_secret", s.clientSecret)

	resp, err := doRequest("POST", cfg.TokenEndpoint,
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(data.Encode()))
	if err != nil {
		return authprovider.AuthIdentity{}, err
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.Unmarshal(resp.Body, &tokenResp); err != nil {
		return authprovider.AuthIdentity{}, fmt.Errorf("oidc: decoding token response: %w", err)
	}
	if tokenResp.Error != "" {
		return authprovider.AuthIdentity{}, fmt.Errorf("oidc: token error: %s - %s", tokenResp.Error, tokenResp.ErrorDesc)
	}
	if tokenResp.IDToken == "" {
		return authprovider.AuthIdentity{}, errors.New("oidc: token response did not include an ID token")
	}

	c, err := verifyIDToken(s, cfg, tokenResp.IDToken, req.Nonce)
	if err != nil {
		return authprovider.AuthIdentity{}, err
	}

	return buildIdentity(s, c, tokenResp.IDToken), nil
}

// VerifyBearer validates a bearer token and returns the authenticated identity.
func (*oidcPlugin) VerifyBearer(req authprovider.VerifyBearerRequest) (authprovider.AuthIdentity, error) {
	s := readConfig()
	if !s.enabled() {
		return authprovider.AuthIdentity{}, errors.New("oidc: provider is not enabled")
	}

	cfg, err := discovery(s)
	if err != nil {
		return authprovider.AuthIdentity{}, err
	}

	c, err := verifyIDToken(s, cfg, req.Token, "")
	if err != nil {
		return authprovider.AuthIdentity{}, fmt.Errorf("oidc: bearer token verification: %w", err)
	}

	return buildIdentity(s, c, req.Token), nil
}

// GetLogoutURL returns the provider's single sign-out URL.
func (*oidcPlugin) GetLogoutURL(req authprovider.GetLogoutURLRequest) (authprovider.GetLogoutURLResponse, error) {
	s := readConfig()
	cfg, err := discovery(s)
	if err != nil {
		return authprovider.GetLogoutURLResponse{}, err
	}
	u := buildLogoutURL(cfg, req.PostLogoutRedirectURI, req.IDTokenHint)
	return authprovider.GetLogoutURLResponse{LogoutURL: u}, nil
}

// Required main function - init() handles registration
func main() {}