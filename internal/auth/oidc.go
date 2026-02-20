package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/judsenb/gatekeeper/internal/models"
	"github.com/judsenb/gatekeeper/internal/secrets"
)

// Wraps the OIDC flow. Re-reads config from settings DB on Refresh(),
// so admin changes take effect without a restart.
type OIDCProvider struct {
	mu       sync.RWMutex
	provider *oidc.Provider
	config   oauth2.Config
	verifier *oidc.IDTokenVerifier

	issuer       string
	clientID     string
	clientSecret string
	redirectURL  string
}

type OIDCClaims struct {
	Subject           string   `json:"sub"`
	PreferredUsername string   `json:"preferred_username"`
	Name              string   `json:"name"`
	Email             string   `json:"email"`
	Groups            []string `json:"groups"`
}

func NewOIDCProvider() *OIDCProvider {
	return &OIDCProvider{}
}

// Reloads OIDC config from DB, re-runs discovery if anything changed.
func (p *OIDCProvider) Refresh(settings *models.SettingStore, secretsBackend secrets.Backend) error {
	issuer := strings.TrimSpace(settings.Get(models.SettingOIDCIssuer, ""))
	clientID := strings.TrimSpace(settings.Get(models.SettingOIDCClientID, ""))
	clientSecret := settings.Get(models.SettingOIDCClientSecret, "")
	if secretsBackend != nil {
		if s, err := secretsBackend.GetSecret(secrets.KeyOIDCClientSecret); err == nil && s != "" {
			clientSecret = s
		}
	}
	redirectURL := strings.TrimSpace(settings.Get(models.SettingOIDCRedirectURL, ""))

	if issuer == "" || clientID == "" {
		return fmt.Errorf("OIDC issuer and client_id are required")
	}

	p.mu.RLock()
	unchanged := p.issuer == issuer && p.clientID == clientID &&
		p.clientSecret == clientSecret && p.redirectURL == redirectURL && p.provider != nil
	p.mu.RUnlock()

	if unchanged {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return fmt.Errorf("oidc discovery failed for %s: %w", issuer, err)
	}

	oauthCfg := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})

	p.mu.Lock()
	p.provider = provider
	p.config = oauthCfg
	p.verifier = verifier
	p.issuer = issuer
	p.clientID = clientID
	p.clientSecret = clientSecret
	p.redirectURL = redirectURL
	p.mu.Unlock()

	return nil
}

func (p *OIDCProvider) IsConfigured() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.provider != nil
}

// Returns the IdP auth URL. Don't forget to verify the state param on callback.
func (p *OIDCProvider) AuthCodeURL(state string) (string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.provider == nil {
		return "", fmt.Errorf("OIDC provider not configured")
	}
	return p.config.AuthCodeURL(state, oauth2.AccessTypeOffline), nil
}

// Trades an auth code for tokens, verifies the id_token, returns claims.
func (p *OIDCProvider) Exchange(ctx context.Context, code string) (*OIDCClaims, error) {
	p.mu.RLock()
	cfg := p.config
	verifier := p.verifier
	p.mu.RUnlock()

	if verifier == nil {
		return nil, fmt.Errorf("OIDC provider not configured")
	}

	token, err := cfg.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in response")
	}

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("id_token verification failed: %w", err)
	}

	var claims OIDCClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	// not every IdP sends preferred_username, fall back to whatever we can get
	if claims.PreferredUsername == "" {
		if claims.Email != "" {
			claims.PreferredUsername = claims.Email
		} else {
			claims.PreferredUsername = claims.Subject
		}
	}
	if claims.Name == "" {
		claims.Name = claims.PreferredUsername
	}

	return &claims, nil
}

func GenerateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
