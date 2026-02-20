package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/judsenb/gatekeeper/internal/db"
)

const mfaPendingTTL = 5 * time.Minute

// Short-lived token that lives between password check and MFA verification.
type MFAPendingStore struct {
	DB *db.DB
}

func (s *MFAPendingStore) Create(userID, ip, userAgent string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate mfa token: %w", err)
	}
	token := hex.EncodeToString(raw)

	hash := hashMFAToken(token)
	expiresAt := time.Now().UTC().Add(mfaPendingTTL)

	_, err := s.DB.Exec(`INSERT INTO mfa_pending (token_hash, user_id, ip, user_agent, expires_at)
		VALUES (?, ?, ?, ?, ?)`, hash, userID, ip, userAgent, expiresAt.Format(time.RFC3339))
	if err != nil {
		return "", fmt.Errorf("insert mfa_pending: %w", err)
	}
	return token, nil
}

// Single-use: token is consumed on successful validation.
func (s *MFAPendingStore) Validate(token string) (string, error) {
	hash := hashMFAToken(token)

	var userID, expiresAtStr string
	err := s.DB.QueryRow(`SELECT user_id, expires_at FROM mfa_pending WHERE token_hash = ?`, hash).
		Scan(&userID, &expiresAtStr)
	if err != nil {
		return "", fmt.Errorf("invalid mfa token")
	}

	expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
	if err != nil {
		expiresAt, err = time.Parse("2006-01-02 15:04:05", expiresAtStr)
		if err != nil {
			return "", fmt.Errorf("parse mfa expiry: %w", err)
		}
	}

	if time.Now().UTC().After(expiresAt) {
		s.DB.Exec("DELETE FROM mfa_pending WHERE token_hash = ?", hash)
		return "", fmt.Errorf("mfa token expired")
	}

	s.DB.Exec("DELETE FROM mfa_pending WHERE token_hash = ?", hash)

	return userID, nil
}

func (s *MFAPendingStore) Cleanup() error {
	_, err := s.DB.Exec("DELETE FROM mfa_pending WHERE expires_at < ?",
		time.Now().UTC().Format(time.RFC3339))
	return err
}

func hashMFAToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
