package models

import (
	"fmt"
	"strings"
	"time"

	"github.com/judsenb/gatekeeper/internal/db"
	"github.com/judsenb/gatekeeper/internal/id"
)

type Host struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Hostname         string   `json:"hostname"`
	Port             int      `json:"port"`
	OS               string   `json:"os"`
	VLAN             string   `json:"vlan"`
	Subnet           string   `json:"subnet"`
	Protocols        []string `json:"protocols"`
	Online           bool     `json:"online"`
	SSHUser          string   `json:"ssh_user"`
	SSHAuthMethod    string   `json:"ssh_auth_method"` // "password" or "key"
	SSHPassword      string   `json:"ssh_password,omitempty"`
	SSHKeyID         string   `json:"ssh_key_id"`
	Disabled         bool     `json:"disabled"`
	RequireReason    bool     `json:"require_reason"`
	RequiresApproval bool     `json:"requires_approval"`
	CreatedAt        string   `json:"created_at"`
	UpdatedAt        string   `json:"updated_at"`
	InUseBy          string   `json:"in_use_by,omitempty"` // username of active session, if any (set by API, not stored in DB)
}

type HostStore struct {
	DB *db.DB
}

func (s *HostStore) List() ([]Host, error) {
	rows, err := s.DB.Query(`
		SELECT id, name, hostname, port, os, vlan, subnet, protocols, online,
		       ssh_user, ssh_auth_method, ssh_password, ssh_key_id,
		       disabled, COALESCE(require_reason, 0), COALESCE(requires_approval, 0), created_at, updated_at
		FROM hosts ORDER BY vlan, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []Host
	for rows.Next() {
		var h Host
		var protocols string
		var online, disabled, reqReason, reqApproval int
		if err := rows.Scan(&h.ID, &h.Name, &h.Hostname, &h.Port, &h.OS,
			&h.VLAN, &h.Subnet, &protocols, &online,
			&h.SSHUser, &h.SSHAuthMethod, &h.SSHPassword, &h.SSHKeyID,
			&disabled, &reqReason, &reqApproval, &h.CreatedAt, &h.UpdatedAt); err != nil {
			return nil, err
		}
		h.Protocols = splitCSV(protocols)
		h.Online = online == 1
		h.Disabled = disabled != 0
		h.RequireReason = reqReason != 0
		h.RequiresApproval = reqApproval != 0
		hosts = append(hosts, h)
	}
	return hosts, rows.Err()
}

func (s *HostStore) GetByID(id string) (*Host, error) {
	var h Host
	var protocols string
	var online, disabled, reqReason, reqApproval int
	err := s.DB.QueryRow(`
		SELECT id, name, hostname, port, os, vlan, subnet, protocols, online,
		       ssh_user, ssh_auth_method, ssh_password, ssh_key_id,
		       disabled, COALESCE(require_reason, 0), COALESCE(requires_approval, 0), created_at, updated_at
		FROM hosts WHERE id = ?`, id).Scan(
		&h.ID, &h.Name, &h.Hostname, &h.Port, &h.OS,
		&h.VLAN, &h.Subnet, &protocols, &online,
		&h.SSHUser, &h.SSHAuthMethod, &h.SSHPassword, &h.SSHKeyID,
		&disabled, &reqReason, &reqApproval, &h.CreatedAt, &h.UpdatedAt)
	if err != nil {
		return nil, err
	}
	h.Protocols = splitCSV(protocols)
	h.Online = online == 1
	h.Disabled = disabled != 0
	h.RequireReason = reqReason != 0
	h.RequiresApproval = reqApproval != 0
	return &h, nil
}

func (s *HostStore) Create(h *Host) error {
	if h.ID == "" {
		newID, err := id.New()
		if err != nil {
			return fmt.Errorf("generate host id: %w", err)
		}
		h.ID = newID
	}
	now := time.Now().UTC().Format(time.RFC3339)
	h.CreatedAt = now
	h.UpdatedAt = now
	if h.Port == 0 {
		h.Port = 22
	}

	if h.SSHAuthMethod == "" {
		h.SSHAuthMethod = "password"
	}
	_, err := s.DB.Exec(`
		INSERT INTO hosts (id, name, hostname, port, os, vlan, subnet, protocols, online,
		                   ssh_user, ssh_auth_method, ssh_password, ssh_key_id,
		                   disabled, require_reason, requires_approval, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		h.ID, h.Name, h.Hostname, h.Port, h.OS, h.VLAN, h.Subnet,
		joinCSV(h.Protocols), boolToInt(h.Online),
		h.SSHUser, h.SSHAuthMethod, h.SSHPassword, h.SSHKeyID,
		boolToInt(h.Disabled), boolToInt(h.RequireReason), boolToInt(h.RequiresApproval), h.CreatedAt, h.UpdatedAt)
	return err
}

func (s *HostStore) Update(h *Host) error {
	h.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if h.SSHAuthMethod == "" {
		h.SSHAuthMethod = "password"
	}
	_, err := s.DB.Exec(`
		UPDATE hosts SET name=?, hostname=?, port=?, os=?, vlan=?, subnet=?, protocols=?, online=?,
		               ssh_user=?, ssh_auth_method=?, ssh_password=?, ssh_key_id=?,
		               disabled=?, require_reason=?, requires_approval=?, updated_at=?
		WHERE id=?`,
		h.Name, h.Hostname, h.Port, h.OS, h.VLAN, h.Subnet,
		joinCSV(h.Protocols), boolToInt(h.Online),
		h.SSHUser, h.SSHAuthMethod, h.SSHPassword, h.SSHKeyID,
		boolToInt(h.Disabled), boolToInt(h.RequireReason), boolToInt(h.RequiresApproval), h.UpdatedAt, h.ID)
	return err
}

func (s *HostStore) Delete(id string) error {
	res, err := s.DB.Exec("DELETE FROM hosts WHERE id = ?", id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("host not found")
	}
	return nil
}

func (s *HostStore) SetOnline(hostID string, online bool) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.DB.Exec("UPDATE hosts SET online = ?, updated_at = ? WHERE id = ?",
		boolToInt(online), now, hostID)
	return err
}

func (s *HostStore) SetDisabled(hostID string, disabled bool) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.DB.Exec("UPDATE hosts SET disabled = ?, updated_at = ? WHERE id = ?",
		boolToInt(disabled), now, hostID)
	return err
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func joinCSV(ss []string) string {
	return strings.Join(ss, ",")
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
