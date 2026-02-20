package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/judsenb/gatekeeper/internal/db"
)

type Session struct {
	TokenHash string
	UserID    string
	IP        string
	UserAgent string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type SessionStore struct {
	DB       *db.DB
	Duration time.Duration // session lifetime, e.g. 24h
}

func NewSessionStore(database *db.DB, duration time.Duration) *SessionStore {
	return &SessionStore{DB: database, Duration: duration}
}

// Returns the raw (unhashed) token; only the SHA-256 is stored.
func (s *SessionStore) Create(userID, ip, userAgent string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	token := hex.EncodeToString(raw)

	hash := hashToken(token)
	expiresAt := time.Now().UTC().Add(s.Duration)

	_, err := s.DB.Exec(`INSERT INTO auth_sessions (token_hash, user_id, ip, user_agent, expires_at)
		VALUES (?, ?, ?, ?, ?)`, hash, userID, ip, userAgent, expiresAt.Format(time.RFC3339))
	if err != nil {
		return "", fmt.Errorf("insert session: %w", err)
	}
	return token, nil
}

func (s *SessionStore) Validate(token string) (string, error) {
	hash := hashToken(token)

	var userID string
	var expiresAtStr string
	err := s.DB.QueryRow(`SELECT user_id, expires_at FROM auth_sessions WHERE token_hash = ?`, hash).
		Scan(&userID, &expiresAtStr)
	if err != nil {
		return "", err // sql.ErrNoRows → invalid token
	}

	expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
	if err != nil {
		// sqlite sometimes hands back a different time format because of course it does
		expiresAt, err = time.Parse("2006-01-02 15:04:05", expiresAtStr)
		if err != nil {
			return "", fmt.Errorf("parse expiry: %w", err)
		}
	}

	if time.Now().UTC().After(expiresAt) {
		// expired — try to clean up but don't sweat it if the delete fails
		if _, err := s.DB.Exec("DELETE FROM auth_sessions WHERE token_hash = ?", hash); err != nil {
			slog.Debug("auth session cleanup delete failed", "err", err)
		}
		return "", fmt.Errorf("session expired")
	}

	return userID, nil
}

func (s *SessionStore) Destroy(token string) error {
	hash := hashToken(token)
	_, err := s.DB.Exec("DELETE FROM auth_sessions WHERE token_hash = ?", hash)
	return err
}

// Force-logout: kills every session for this user.
func (s *SessionStore) DestroyAllForUser(userID string) error {
	_, err := s.DB.Exec("DELETE FROM auth_sessions WHERE user_id = ?", userID)
	return err
}

func (s *SessionStore) Cleanup() error {
	_, err := s.DB.Exec("DELETE FROM auth_sessions WHERE expires_at < ?",
		time.Now().UTC().Format(time.RFC3339))
	return err
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
