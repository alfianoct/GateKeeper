package models

import (
	"fmt"
	"time"

	"github.com/judsenb/gatekeeper/internal/audit"
	"github.com/judsenb/gatekeeper/internal/db"
	"github.com/judsenb/gatekeeper/internal/instance"
	"github.com/judsenb/gatekeeper/internal/metrics"
)

type AuditEntry struct {
	ID        int64  `json:"id"`
	Timestamp string `json:"timestamp"`
	Action    string `json:"action"`
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	TargetID  string `json:"target_id"`
	Target    string `json:"target"`
	Detail    string `json:"detail"`
	SourceIP  string `json:"source_ip"`
	SessionID string `json:"session_id"`
	Reason    string `json:"reason,omitempty"`
}

type AuditStore struct {
	DB         *db.DB
	Dispatcher *audit.Dispatcher
}

func (s *AuditStore) Log(entry *AuditEntry) error {
	metrics.AuditEvents.Add(1)
	entry.Timestamp = time.Now().UTC().Format(time.RFC3339)
	iid := instance.ID()

	if s.DB.Driver == "postgres" {
		err := s.DB.QueryRow(`
			INSERT INTO audit_log (timestamp, action, user_id, username, target_id, target, detail, source_ip, session_id, reason, instance_id)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
			entry.Timestamp, entry.Action, entry.UserID, entry.Username,
			entry.TargetID, entry.Target, entry.Detail, entry.SourceIP, entry.SessionID, entry.Reason, iid).Scan(&entry.ID)
		if err == nil {
			s.dispatch(entry)
		}
		return err
	}

	res, err := s.DB.Exec(`
		INSERT INTO audit_log (timestamp, action, user_id, username, target_id, target, detail, source_ip, session_id, reason, instance_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.Timestamp, entry.Action, entry.UserID, entry.Username,
		entry.TargetID, entry.Target, entry.Detail, entry.SourceIP, entry.SessionID, entry.Reason, iid)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("audit insert: %w", err)
	}
	entry.ID = id

	s.dispatch(entry)
	return nil
}

func (s *AuditStore) dispatch(entry *AuditEntry) {
	if s.Dispatcher == nil {
		return
	}
	s.Dispatcher.Send(audit.Event{
		Timestamp:  entry.Timestamp,
		Action:     entry.Action,
		UserID:     entry.UserID,
		Username:   entry.Username,
		TargetID:   entry.TargetID,
		Target:     entry.Target,
		Detail:     entry.Detail,
		SourceIP:   entry.SourceIP,
		SessionID:  entry.SessionID,
		Reason:     entry.Reason,
		InstanceID: instance.ID(),
	})
}

func (s *AuditStore) List(action string, limit, offset int) ([]AuditEntry, error) {
	query := `SELECT id, timestamp, action, user_id, username, target_id, target, detail, source_ip, session_id, COALESCE(reason, '')
		FROM audit_log`
	args := []any{}

	if action != "" {
		query += " WHERE action = ?"
		args = append(args, action)
	}

	query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := s.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Action, &e.UserID, &e.Username,
			&e.TargetID, &e.Target, &e.Detail, &e.SourceIP, &e.SessionID, &e.Reason); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func (s *AuditStore) ListRange(from, to string, limit int) ([]AuditEntry, error) {
	query := `SELECT id, timestamp, action, user_id, username, target_id, target, detail, source_ip, session_id, COALESCE(reason, '')
		FROM audit_log`
	args := []any{}
	clauses := []string{}

	if from != "" {
		clauses = append(clauses, "timestamp >= ?")
		args = append(args, from)
	}
	if to != "" {
		clauses = append(clauses, "timestamp <= ?")
		args = append(args, to)
	}
	if len(clauses) > 0 {
		query += " WHERE " + clauses[0]
		for _, c := range clauses[1:] {
			query += " AND " + c
		}
	}

	query += " ORDER BY timestamp DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Action, &e.UserID, &e.Username,
			&e.TargetID, &e.Target, &e.Detail, &e.SourceIP, &e.SessionID, &e.Reason); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
