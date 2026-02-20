package models

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/judsenb/gatekeeper/internal/db"
	"github.com/judsenb/gatekeeper/internal/id"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID                string  `json:"id"`
	Username          string  `json:"username"`
	DisplayName       string  `json:"display_name"`
	PasswordHash      string  `json:"-"`
	Role              string  `json:"role"`
	Groups            string  `json:"groups"`
	AuthProvider      string  `json:"auth_provider"`
	OIDCSubject       string  `json:"oidc_subject,omitempty"`
	Disabled          bool    `json:"disabled"`
	CreatedAt         string  `json:"created_at"`
	LastLoginAt       *string `json:"last_login_at"`
	MFAEnabled        bool    `json:"mfa_enabled"`
	MFASecret         string  `json:"-"`
	MFARecoveryCodes  string  `json:"-"`
	PasswordChangedAt string  `json:"-"`
}

type UserStore struct {
	DB *db.DB
}

func (s *UserStore) List() ([]User, error) {
	rows, err := s.DB.Query(`SELECT id, username, display_name, role, groups_csv,
		auth_provider, oidc_subject, disabled, created_at, last_login_at, mfa_enabled
		FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		var disabled, mfaEnabled int
		if err := rows.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Role, &u.Groups,
			&u.AuthProvider, &u.OIDCSubject, &disabled, &u.CreatedAt, &u.LastLoginAt, &mfaEnabled); err != nil {
			return nil, err
		}
		u.Disabled = disabled != 0
		u.MFAEnabled = mfaEnabled != 0
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *UserStore) GetByID(userID string) (*User, error) {
	var u User
	var disabled, mfaEnabled int
	err := s.DB.QueryRow(`SELECT id, username, display_name, password_hash, role, groups_csv,
		auth_provider, oidc_subject, disabled, created_at, last_login_at,
		mfa_enabled, mfa_secret, mfa_recovery_codes, password_changed_at
		FROM users WHERE id = ?`, userID).Scan(
		&u.ID, &u.Username, &u.DisplayName, &u.PasswordHash, &u.Role, &u.Groups,
		&u.AuthProvider, &u.OIDCSubject, &disabled, &u.CreatedAt, &u.LastLoginAt,
		&mfaEnabled, &u.MFASecret, &u.MFARecoveryCodes, &u.PasswordChangedAt)
	if err != nil {
		return nil, err
	}
	u.Disabled = disabled != 0
	u.MFAEnabled = mfaEnabled != 0
	return &u, nil
}

func (s *UserStore) GetByUsername(username string) (*User, error) {
	var u User
	var disabled, mfaEnabled int
	err := s.DB.QueryRow(`SELECT id, username, display_name, password_hash, role, groups_csv,
		auth_provider, oidc_subject, disabled, created_at, last_login_at,
		mfa_enabled, mfa_secret, mfa_recovery_codes, password_changed_at
		FROM users WHERE username = ?`, username).Scan(
		&u.ID, &u.Username, &u.DisplayName, &u.PasswordHash, &u.Role, &u.Groups,
		&u.AuthProvider, &u.OIDCSubject, &disabled, &u.CreatedAt, &u.LastLoginAt,
		&mfaEnabled, &u.MFASecret, &u.MFARecoveryCodes, &u.PasswordChangedAt)
	if err != nil {
		return nil, err
	}
	u.Disabled = disabled != 0
	u.MFAEnabled = mfaEnabled != 0
	return &u, nil
}

// Create hashes the password and inserts. don't pass already-hashed strings.
func (s *UserStore) Create(u *User, plainPassword string) error {
	if u.ID == "" {
		newID, err := id.New()
		if err != nil {
			return fmt.Errorf("generate user id: %w", err)
		}
		u.ID = newID
	}
	if u.Role == "" {
		u.Role = "user"
	}
	if u.AuthProvider == "" {
		u.AuthProvider = "local"
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	u.PasswordHash = string(hash)
	u.PasswordChangedAt = time.Now().UTC().Format(time.RFC3339)

	_, err = s.DB.Exec(`INSERT INTO users (id, username, display_name, password_hash, role,
		groups_csv, auth_provider, oidc_subject, disabled, password_changed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Username, u.DisplayName, u.PasswordHash, u.Role,
		u.Groups, u.AuthProvider, u.OIDCSubject, boolToInt(u.Disabled), u.PasswordChangedAt)
	return err
}

func (s *UserStore) CreateOIDC(u *User) error {
	if u.ID == "" {
		newID, err := id.New()
		if err != nil {
			return fmt.Errorf("generate user id: %w", err)
		}
		u.ID = newID
	}
	u.AuthProvider = "oidc"

	_, err := s.DB.Exec(`INSERT INTO users (id, username, display_name, password_hash, role,
		groups_csv, auth_provider, oidc_subject, disabled)
		VALUES (?, ?, ?, '', ?, ?, 'oidc', ?, ?)`,
		u.ID, u.Username, u.DisplayName, u.Role, u.Groups, u.OIDCSubject, boolToInt(u.Disabled))
	return err
}

// Update changes profile fields. does NOT touch the password.
func (s *UserStore) Update(u *User) error {
	_, err := s.DB.Exec(`UPDATE users SET display_name = ?, role = ?, groups_csv = ?,
		disabled = ? WHERE id = ?`,
		u.DisplayName, u.Role, u.Groups, boolToInt(u.Disabled), u.ID)
	return err
}

func (s *UserStore) SetPassword(userID, plainPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = s.DB.Exec("UPDATE users SET password_hash = ?, password_changed_at = ? WHERE id = ?", string(hash), now, userID)
	return err
}

// SetMFASecret stores the TOTP secret during enrollment (not yet confirmed).
func (s *UserStore) SetMFASecret(userID, secret string) error {
	_, err := s.DB.Exec("UPDATE users SET mfa_secret = ? WHERE id = ?", secret, userID)
	return err
}

func (s *UserStore) EnableMFA(userID, recoveryCodes string) error {
	_, err := s.DB.Exec("UPDATE users SET mfa_enabled = 1, mfa_recovery_codes = ? WHERE id = ?", recoveryCodes, userID)
	return err
}

func (s *UserStore) DisableMFA(userID string) error {
	_, err := s.DB.Exec("UPDATE users SET mfa_enabled = 0, mfa_secret = '', mfa_recovery_codes = '' WHERE id = ?", userID)
	return err
}

func (s *UserStore) UpdateRecoveryCodes(userID, codes string) error {
	_, err := s.DB.Exec("UPDATE users SET mfa_recovery_codes = ? WHERE id = ?", codes, userID)
	return err
}

func (s *UserStore) AddPasswordHistory(userID, passwordHash string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.DB.Exec("INSERT INTO password_history (user_id, password_hash, created_at) VALUES (?, ?, ?)",
		userID, passwordHash, now)
	return err
}

// CheckPasswordHistory returns true if the password matches any of the last N.
func (s *UserStore) CheckPasswordHistory(userID, plainPassword string, count int) (bool, error) {
	if count <= 0 {
		return false, nil
	}
	rows, err := s.DB.Query(
		"SELECT password_hash FROM password_history WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
		userID, count)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return false, err
		}
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(plainPassword)) == nil {
			return true, nil
		}
	}
	return false, rows.Err()
}

func (s *UserStore) Delete(userID string) error {
	res, err := s.DB.Exec("DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

func (s *UserStore) CheckPassword(user *User, plainPassword string) bool {
	return bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(plainPassword)) == nil
}

func (s *UserStore) TouchLogin(userID string) {
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.DB.Exec("UPDATE users SET last_login_at = ? WHERE id = ?", now, userID); err != nil {
		slog.Debug("touch login failed", "user_id", userID, "err", err)
	}
}

func (s *UserStore) Count() (int, error) {
	var count int
	err := s.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	return count, err
}

func (s *UserStore) GetByOIDCSubject(sub string) (*User, error) {
	return s.GetByAuthProviderAndSubject("oidc", sub)
}

func (s *UserStore) GetByAuthProviderAndSubject(provider, subject string) (*User, error) {
	if provider == "" || subject == "" {
		return nil, fmt.Errorf("provider and subject required")
	}
	var u User
	var disabled, mfaEnabled int
	err := s.DB.QueryRow(`SELECT id, username, display_name, password_hash, role, groups_csv,
		auth_provider, oidc_subject, disabled, created_at, last_login_at,
		mfa_enabled, mfa_secret, mfa_recovery_codes, password_changed_at
		FROM users WHERE oidc_subject = ? AND auth_provider = ?`, subject, provider).Scan(
		&u.ID, &u.Username, &u.DisplayName, &u.PasswordHash, &u.Role, &u.Groups,
		&u.AuthProvider, &u.OIDCSubject, &disabled, &u.CreatedAt, &u.LastLoginAt,
		&mfaEnabled, &u.MFASecret, &u.MFARecoveryCodes, &u.PasswordChangedAt)
	if err != nil {
		return nil, err
	}
	u.Disabled = disabled != 0
	u.MFAEnabled = mfaEnabled != 0
	return &u, nil
}

// CreateExternal inserts a user from LDAP/etc. oidc_subject column stores the external id.
func (s *UserStore) CreateExternal(u *User, provider string) error {
	if u.ID == "" {
		newID, err := id.New()
		if err != nil {
			return fmt.Errorf("generate user id: %w", err)
		}
		u.ID = newID
	}
	u.AuthProvider = provider
	_, err := s.DB.Exec(`INSERT INTO users (id, username, display_name, password_hash, role,
		groups_csv, auth_provider, oidc_subject, disabled)
		VALUES (?, ?, ?, '', ?, ?, ?, ?, ?)`,
		u.ID, u.Username, u.DisplayName, u.Role, u.Groups, u.AuthProvider, u.OIDCSubject, boolToInt(u.Disabled))
	return err
}
