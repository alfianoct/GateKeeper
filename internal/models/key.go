package models

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/judsenb/gatekeeper/internal/db"
	"github.com/judsenb/gatekeeper/internal/id"
)

type SSHKey struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	KeyType     string  `json:"key_type"`
	PublicKey   string  `json:"public_key"`
	PrivateKey  string  `json:"private_key,omitempty"` // PEM-encoded, never returned in list
	Fingerprint string  `json:"fingerprint"`
	UserID      string  `json:"user_id"`
	IsSystem    bool    `json:"is_system"`
	AddedAt     string  `json:"added_at"`
	LastUsedAt  *string `json:"last_used_at"`
}

type KeyStore struct {
	DB *db.DB
}

func (s *KeyStore) List() ([]SSHKey, error) {
	rows, err := s.DB.Query(`
		SELECT id, name, key_type, public_key, fingerprint, user_id, is_system, added_at, last_used_at
		FROM ssh_keys ORDER BY added_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []SSHKey
	for rows.Next() {
		var k SSHKey
		var isSystem int
		if err := rows.Scan(&k.ID, &k.Name, &k.KeyType, &k.PublicKey, &k.Fingerprint,
			&k.UserID, &isSystem, &k.AddedAt, &k.LastUsedAt); err != nil {
			return nil, err
		}
		k.IsSystem = isSystem == 1
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

func (s *KeyStore) Create(k *SSHKey) error {
	if k.ID == "" {
		newID, err := id.New()
		if err != nil {
			return fmt.Errorf("generate key id: %w", err)
		}
		k.ID = newID
	}
	k.AddedAt = time.Now().UTC().Format(time.RFC3339)
	if k.Fingerprint == "" && k.PublicKey != "" {
		k.Fingerprint = computeFingerprint(k.PublicKey)
	}
	_, err := s.DB.Exec(`
		INSERT INTO ssh_keys (id, name, key_type, public_key, private_key, fingerprint, user_id, is_system, added_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		k.ID, k.Name, k.KeyType, k.PublicKey, k.PrivateKey, k.Fingerprint, k.UserID, boolToInt(k.IsSystem), k.AddedAt)
	return err
}

func (s *KeyStore) GetByID(keyID string) (*SSHKey, error) {
	var k SSHKey
	var isSystem int
	err := s.DB.QueryRow(`
		SELECT id, name, key_type, public_key, private_key, fingerprint, user_id, is_system, added_at, last_used_at
		FROM ssh_keys WHERE id = ?`, keyID).Scan(
		&k.ID, &k.Name, &k.KeyType, &k.PublicKey, &k.PrivateKey, &k.Fingerprint,
		&k.UserID, &isSystem, &k.AddedAt, &k.LastUsedAt)
	if err != nil {
		return nil, err
	}
	k.IsSystem = isSystem == 1
	return &k, nil
}

func (s *KeyStore) GetByUserID(userID string) ([]SSHKey, error) {
	rows, err := s.DB.Query(`
		SELECT id, name, key_type, public_key, private_key, fingerprint, user_id, is_system, added_at, last_used_at
		FROM ssh_keys
		WHERE user_id = ? OR is_system = 1
		ORDER BY added_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []SSHKey
	for rows.Next() {
		var k SSHKey
		var isSystem int
		if err := rows.Scan(&k.ID, &k.Name, &k.KeyType, &k.PublicKey, &k.PrivateKey, &k.Fingerprint,
			&k.UserID, &isSystem, &k.AddedAt, &k.LastUsedAt); err != nil {
			return nil, err
		}
		k.IsSystem = isSystem == 1
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

func (s *KeyStore) Delete(keyID string) error {
	res, err := s.DB.Exec("DELETE FROM ssh_keys WHERE id = ? AND is_system = 0", keyID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("key not found or is a system key")
	}
	return nil
}

func (s *KeyStore) TouchLastUsed(keyID string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.DB.Exec("UPDATE ssh_keys SET last_used_at = ? WHERE id = ?", now, keyID)
	return err
}

// computeFingerprint extracts the key blob from "type base64 comment" format
func computeFingerprint(pubKey string) string {
	parts := strings.Fields(pubKey)
	var keyData []byte
	if len(parts) >= 2 {
		decoded, err := base64.StdEncoding.DecodeString(parts[1])
		if err == nil {
			keyData = decoded
		}
	}
	if len(keyData) == 0 {
		keyData = []byte(pubKey)
	}
	hash := sha256.Sum256(keyData)
	return "SHA256:" + base64.StdEncoding.EncodeToString(hash[:])
}
