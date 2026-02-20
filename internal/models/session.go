package models

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/judsenb/gatekeeper/internal/db"
	"github.com/judsenb/gatekeeper/internal/id"
	"github.com/judsenb/gatekeeper/internal/instance"
)

type Session struct {
	ID           string  `json:"id"`
	UserID       string  `json:"user_id"`
	Username     string  `json:"username"`
	HostID       string  `json:"host_id"`
	HostName     string  `json:"host_name"`
	HostAddr     string  `json:"host_addr"`
	Protocol     string  `json:"protocol"`
	ConnectedAt  string  `json:"connected_at"`
	ClosedAt     *string `json:"closed_at"`
	BytesTX      int64   `json:"bytes_tx"`
	BytesRX      int64   `json:"bytes_rx"`
	Recording    string  `json:"-"`
	HasRecording bool    `json:"has_recording"`
	Reason       string  `json:"reason,omitempty"`
}

type SessionStore struct {
	DB *db.DB
}

func (s *SessionStore) ListActive() ([]Session, error) {
	return s.query("SELECT id, user_id, username, host_id, host_name, host_addr, protocol, connected_at, closed_at, bytes_tx, bytes_rx, recording, COALESCE(reason, '') FROM sessions WHERE closed_at IS NULL ORDER BY connected_at DESC")
}

// GetActiveByHostID enforces one-user-per-host. also used for admin takeover.
func (s *SessionStore) GetActiveByHostID(hostID string) (*Session, error) {
	rows, err := s.DB.Query(`
		SELECT id, user_id, username, host_id, host_name, host_addr, protocol, connected_at, closed_at, bytes_tx, bytes_rx, recording, COALESCE(reason, '')
		FROM sessions WHERE host_id = ? AND closed_at IS NULL ORDER BY connected_at DESC LIMIT 1`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, nil // no active session
	}
	var sess Session
	if err := rows.Scan(&sess.ID, &sess.UserID, &sess.Username, &sess.HostID,
		&sess.HostName, &sess.HostAddr, &sess.Protocol, &sess.ConnectedAt,
		&sess.ClosedAt, &sess.BytesTX, &sess.BytesRX, &sess.Recording, &sess.Reason); err != nil {
		return nil, err
	}
	sess.HasRecording = sess.Recording != ""
	return &sess, nil
}

func (s *SessionStore) ListHistory(limit int) ([]Session, error) {
	rows, err := s.DB.Query(`
		SELECT id, user_id, username, host_id, host_name, host_addr, protocol, connected_at, closed_at, bytes_tx, bytes_rx, recording, COALESCE(reason, '')
		FROM sessions WHERE closed_at IS NOT NULL ORDER BY closed_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSessions(rows)
}

func (s *SessionStore) Create(sess *Session) error {
	if sess.ID == "" {
		newID, err := id.Short()
		if err != nil {
			return fmt.Errorf("generate session id: %w", err)
		}
		sess.ID = newID
	}
	sess.ConnectedAt = time.Now().UTC().Format(time.RFC3339)
	_, err := s.DB.Exec(`
		INSERT INTO sessions (id, user_id, username, host_id, host_name, host_addr, protocol, connected_at, bytes_tx, bytes_rx, recording, reason, instance_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.ID, sess.UserID, sess.Username, sess.HostID, sess.HostName, sess.HostAddr,
		sess.Protocol, sess.ConnectedAt, sess.BytesTX, sess.BytesRX, sess.Recording, sess.Reason, instance.ID())
	return err
}

func (s *SessionStore) Close(sessionID string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.DB.Exec("UPDATE sessions SET closed_at = ? WHERE id = ?", now, sessionID)
	return err
}

func (s *SessionStore) UpdateBytes(sessionID string, tx, rx int64) error {
	_, err := s.DB.Exec("UPDATE sessions SET bytes_tx = ?, bytes_rx = ? WHERE id = ?", tx, rx, sessionID)
	return err
}

// CleanupStale closes zombie sessions left over after a crash.
func (s *SessionStore) CleanupStale(maxAge time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-maxAge).Format(time.RFC3339)
	res, err := s.DB.Exec(
		"UPDATE sessions SET closed_at = ? WHERE closed_at IS NULL AND connected_at < ?",
		time.Now().UTC().Format(time.RFC3339), cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *SessionStore) GetByID(sessionID string) (*Session, error) {
	var sess Session
	err := s.DB.QueryRow(`
		SELECT id, user_id, username, host_id, host_name, host_addr, protocol,
		       connected_at, closed_at, bytes_tx, bytes_rx, recording, COALESCE(reason, '')
		FROM sessions WHERE id = ?`, sessionID).Scan(
		&sess.ID, &sess.UserID, &sess.Username, &sess.HostID,
		&sess.HostName, &sess.HostAddr, &sess.Protocol, &sess.ConnectedAt,
		&sess.ClosedAt, &sess.BytesTX, &sess.BytesRX, &sess.Recording, &sess.Reason)
	if err != nil {
		return nil, err
	}
	sess.HasRecording = sess.Recording != ""
	return &sess, nil
}

func (s *SessionStore) CountActiveByUserID(userID string) (int, error) {
	var count int
	err := s.DB.QueryRow("SELECT COUNT(*) FROM sessions WHERE user_id = ? AND closed_at IS NULL", userID).Scan(&count)
	return count, err
}

func (s *SessionStore) query(q string) ([]Session, error) {
	rows, err := s.DB.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSessions(rows)
}

func scanSessions(rows *sql.Rows) ([]Session, error) {
	var sessions []Session
	for rows.Next() {
		var sess Session
		if err := rows.Scan(&sess.ID, &sess.UserID, &sess.Username, &sess.HostID,
			&sess.HostName, &sess.HostAddr, &sess.Protocol, &sess.ConnectedAt,
			&sess.ClosedAt, &sess.BytesTX, &sess.BytesRX, &sess.Recording, &sess.Reason); err != nil {
			return nil, err
		}
		sess.HasRecording = sess.Recording != ""
		sessions = append(sessions, sess)
	}
	return sessions, rows.Err()
}
