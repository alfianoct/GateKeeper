package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"

	"github.com/judsenb/gatekeeper/internal/models"
)

// Makes sure at least one admin exists on first run. Only kicks in when
// the setup wizard was skipped (e.g. pre-configured deployment).
func BootstrapAdmin(users *models.UserStore) error {
	count, err := users.Count()
	if err != nil {
		return fmt.Errorf("count users: %w", err)
	}
	if count > 0 {
		return nil
	}

	pwBytes := make([]byte, 12)
	if _, err := rand.Read(pwBytes); err != nil {
		return fmt.Errorf("generate password: %w", err)
	}
	password := hex.EncodeToString(pwBytes) + "!A" // suffix guarantees the complexity check passes

	admin := &models.User{
		Username:     "admin",
		DisplayName:  "Administrator",
		Role:         "platform-admin",
		Groups:       "platform-admin",
		AuthProvider: "local",
	}

	if err := users.Create(admin, password); err != nil {
		return fmt.Errorf("create admin user: %w", err)
	}

	return nil
}

// Local-only auth. SSO users get bounced with an error.
func Authenticate(users *models.UserStore, username, password string) (*models.User, error) {
	user, err := users.GetByUsername(username)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("invalid credentials")
		}
		return nil, fmt.Errorf("lookup user: %w", err)
	}

	if user.Disabled {
		return nil, fmt.Errorf("account disabled")
	}

	if user.AuthProvider != "local" {
		return nil, fmt.Errorf("this account uses SSO — use the OIDC login")
	}

	if !users.CheckPassword(user, password) {
		return nil, fmt.Errorf("invalid credentials")
	}

	return user, nil
}
