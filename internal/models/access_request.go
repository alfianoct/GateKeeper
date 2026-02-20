package models

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/judsenb/gatekeeper/internal/db"
	"github.com/judsenb/gatekeeper/internal/id"
)

type AccessRequest struct {
	ID        string  `json:"id"`
	UserID    string  `json:"user_id"`
	Username  string  `json:"username"`
	HostID    string  `json:"host_id"`
	Reason    string  `json:"reason"`
	Status    string  `json:"status"` // "pending", "approved", "rejected"
	DecidedBy string  `json:"decided_by"`
	DecidedAt *string `json:"decided_at"`
	CreatedAt string  `json:"created_at"`
}

const ApprovalTTL = time.Hour

type AccessRequestStore struct {
	DB *db.DB
}

func (s *AccessRequestStore) Create(req *AccessRequest) error {
	if req.ID == "" {
		newID, err := id.Short()
		if err != nil {
			return fmt.Errorf("generate request id: %w", err)
		}
		req.ID = newID
	}
	req.Status = "pending"
	req.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	_, err := s.DB.Exec(`
		INSERT INTO access_requests (id, user_id, username, host_id, reason, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		req.ID, req.UserID, req.Username, req.HostID, req.Reason, req.Status, req.CreatedAt)
	return err
}

func (s *AccessRequestStore) GetByID(id string) (*AccessRequest, error) {
	var req AccessRequest
	var decidedAt sql.NullString
	err := s.DB.QueryRow(`
		SELECT id, user_id, username, host_id, reason, status, decided_by, decided_at, created_at
		FROM access_requests WHERE id = ?`, id).Scan(
		&req.ID, &req.UserID, &req.Username, &req.HostID, &req.Reason, &req.Status,
		&req.DecidedBy, &decidedAt, &req.CreatedAt)
	if err != nil {
		return nil, err
	}
	if decidedAt.Valid {
		req.DecidedAt = &decidedAt.String
	}
	return &req, nil
}

func (s *AccessRequestStore) ListPending(limit int) ([]AccessRequest, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.DB.Query(`
		SELECT id, user_id, username, host_id, reason, status, decided_by, decided_at, created_at
		FROM access_requests WHERE status = 'pending' ORDER BY created_at ASC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAccessRequests(rows)
}

func (s *AccessRequestStore) Approve(id, decidedBy string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.DB.Exec("UPDATE access_requests SET status = 'approved', decided_by = ?, decided_at = ? WHERE id = ? AND status = 'pending'",
		decidedBy, now, id)
	return err
}

func (s *AccessRequestStore) Reject(id, decidedBy string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.DB.Exec("UPDATE access_requests SET status = 'rejected', decided_by = ?, decided_at = ? WHERE id = ? AND status = 'pending'",
		decidedBy, now, id)
	return err
}

// HasApprovedRequest checks for a recent approval within the TTL window.
func (s *AccessRequestStore) HasApprovedRequest(userID, hostID string, within time.Duration) (bool, error) {
	cutoff := time.Now().UTC().Add(-within).Format(time.RFC3339)
	var count int
	err := s.DB.QueryRow(`
		SELECT COUNT(*) FROM access_requests
		WHERE user_id = ? AND host_id = ? AND status = 'approved' AND decided_at >= ?`,
		userID, hostID, cutoff).Scan(&count)
	return count > 0, err
}

func scanAccessRequests(rows *sql.Rows) ([]AccessRequest, error) {
	var list []AccessRequest
	for rows.Next() {
		var req AccessRequest
		var decidedAt sql.NullString
		if err := rows.Scan(&req.ID, &req.UserID, &req.Username, &req.HostID, &req.Reason, &req.Status,
			&req.DecidedBy, &decidedAt, &req.CreatedAt); err != nil {
			return nil, err
		}
		if decidedAt.Valid {
			req.DecidedAt = &decidedAt.String
		}
		list = append(list, req)
	}
	return list, rows.Err()
}
