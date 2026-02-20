package models

import (
	"github.com/judsenb/gatekeeper/internal/db"
)

// HostKeyStore handles TOFU (trust on first use) for SSH host keys.
type HostKeyStore struct {
	DB *db.DB
}

func (s *HostKeyStore) Get(hostID, keyType string) (string, error) {
	var pub string
	err := s.DB.QueryRow(
		"SELECT public_key FROM host_keys WHERE host_id = ? AND key_type = ?",
		hostID, keyType,
	).Scan(&pub)
	return pub, err
}

func (s *HostKeyStore) Save(hostID, keyType, publicKey string) error {
	_, err := s.DB.Exec(
		`INSERT INTO host_keys (host_id, key_type, public_key) VALUES (?, ?, ?)
		 ON CONFLICT (host_id, key_type) DO UPDATE SET public_key = EXCLUDED.public_key`,
		hostID, keyType, publicKey,
	)
	return err
}

// DeleteByHostID wipes stored keys so the next connect does fresh TOFU.
func (s *HostKeyStore) DeleteByHostID(hostID string) error {
	_, err := s.DB.Exec("DELETE FROM host_keys WHERE host_id = ?", hostID)
	return err
}
