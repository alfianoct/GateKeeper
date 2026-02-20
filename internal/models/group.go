package models

import (
	"fmt"
	"strings"

	"github.com/judsenb/gatekeeper/internal/db"
	"github.com/judsenb/gatekeeper/internal/id"
)

type Group struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Permissions  []string `json:"permissions"`   // CSV stored: "connect_hosts","view_sessions","view_audit",...
	AllowedHosts string   `json:"allowed_hosts"` // "*" for all, or CSV of host IDs
	MaxSessions  int      `json:"max_sessions"`  // 0 = use global default
	CreatedAt    string   `json:"created_at"`
}

var ValidPermissions = []string{
	"connect_hosts",   // Can SSH into hosts assigned to this group
	"view_sessions",   // Can view live + historical sessions
	"view_audit",      // Can view the audit log
	"manage_sessions", // Can kill (terminate) other users' sessions
	"manage_hosts",    // Can add/edit/delete hosts
	"manage_users",    // Can add/edit/disable/delete users
	"manage_keys",     // Can add/revoke SSH keys
	"manage_groups",   // Can add/edit/delete groups and group mappings
	"manage_settings", // Can modify platform settings
}

type GroupStore struct {
	DB *db.DB
}

func (s *GroupStore) List() ([]Group, error) {
	rows, err := s.DB.Query(`SELECT id, name, description, permissions, allowed_hosts, created_at, COALESCE(max_sessions, 0) FROM groups ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []Group
	for rows.Next() {
		var g Group
		var perms string
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &perms, &g.AllowedHosts, &g.CreatedAt, &g.MaxSessions); err != nil {
			return nil, err
		}
		g.Permissions = splitCSV(perms)
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

func (s *GroupStore) GetByID(groupID string) (*Group, error) {
	var g Group
	var perms string
	err := s.DB.QueryRow(`SELECT id, name, description, permissions, allowed_hosts, created_at, COALESCE(max_sessions, 0) FROM groups WHERE id = ?`, groupID).
		Scan(&g.ID, &g.Name, &g.Description, &perms, &g.AllowedHosts, &g.CreatedAt, &g.MaxSessions)
	if err != nil {
		return nil, err
	}
	g.Permissions = splitCSV(perms)
	return &g, nil
}

func (s *GroupStore) GetByName(name string) (*Group, error) {
	var g Group
	var perms string
	err := s.DB.QueryRow(`SELECT id, name, description, permissions, allowed_hosts, created_at, COALESCE(max_sessions, 0) FROM groups WHERE name = ?`, name).
		Scan(&g.ID, &g.Name, &g.Description, &perms, &g.AllowedHosts, &g.CreatedAt, &g.MaxSessions)
	if err != nil {
		return nil, err
	}
	g.Permissions = splitCSV(perms)
	return &g, nil
}

func (s *GroupStore) Create(g *Group) error {
	if g.ID == "" {
		newID, err := id.New()
		if err != nil {
			return fmt.Errorf("generate group id: %w", err)
		}
		g.ID = newID
	}
	if g.AllowedHosts == "" {
		g.AllowedHosts = "*"
	}
	_, err := s.DB.Exec(`INSERT INTO groups (id, name, description, permissions, allowed_hosts, max_sessions) VALUES (?, ?, ?, ?, ?, ?)`,
		g.ID, g.Name, g.Description, strings.Join(g.Permissions, ","), g.AllowedHosts, g.MaxSessions)
	return err
}

func (s *GroupStore) Update(g *Group) error {
	if g.AllowedHosts == "" {
		g.AllowedHosts = "*"
	}
	res, err := s.DB.Exec(`UPDATE groups SET name = ?, description = ?, permissions = ?, allowed_hosts = ?, max_sessions = ? WHERE id = ?`,
		g.Name, g.Description, strings.Join(g.Permissions, ","), g.AllowedHosts, g.MaxSessions, g.ID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("group not found")
	}
	return nil
}

// CheckAccess returns true if any of the user's groups can reach this host.
// if no groups exist at all, everything is wide open (legacy fallback).
func (s *GroupStore) CheckAccess(userGroups []string, hostID string) (bool, error) {
	var total int
	if err := s.DB.QueryRow("SELECT COUNT(*) FROM groups").Scan(&total); err != nil {
		return false, err
	}
	if total == 0 {
		return true, nil
	}

	for _, groupName := range userGroups {
		var allowedHosts string
		err := s.DB.QueryRow(`SELECT allowed_hosts FROM groups WHERE name = ?`, groupName).Scan(&allowedHosts)
		if err != nil {
			continue // group not found in DB
		}
		if allowedHosts == "*" {
			return true, nil
		}
		if containsCSV(allowedHosts, hostID) {
			return true, nil
		}
	}

	return false, nil
}

func (s *GroupStore) Delete(groupID string) error {
	res, err := s.DB.Exec("DELETE FROM groups WHERE id = ?", groupID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("group not found")
	}
	return nil
}

// HasPermission checks group perms. platform-admins bypass this in middleware.
func (s *GroupStore) HasPermission(userGroups []string, permission string) (bool, error) {
	if len(userGroups) == 0 {
		return false, nil
	}
	for _, groupName := range userGroups {
		var perms string
		err := s.DB.QueryRow(`SELECT permissions FROM groups WHERE name = ?`, groupName).Scan(&perms)
		if err != nil {
			continue // group not found
		}
		for _, p := range strings.Split(perms, ",") {
			if strings.TrimSpace(p) == permission {
				return true, nil
			}
		}
	}
	return false, nil
}

func (s *GroupStore) EffectivePermissions(userGroups []string) ([]string, error) {
	seen := map[string]bool{}
	for _, groupName := range userGroups {
		var perms string
		err := s.DB.QueryRow(`SELECT permissions FROM groups WHERE name = ?`, groupName).Scan(&perms)
		if err != nil {
			continue
		}
		for _, p := range strings.Split(perms, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				seen[p] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	return out, nil
}

// MaxSessionsForUser picks the lowest non-zero limit across groups. 0 = unlimited.
func (s *GroupStore) MaxSessionsForUser(userGroups []string) int {
	limit := 0
	for _, groupName := range userGroups {
		var ms int
		err := s.DB.QueryRow(`SELECT COALESCE(max_sessions, 0) FROM groups WHERE name = ?`, groupName).Scan(&ms)
		if err != nil || ms == 0 {
			continue
		}
		if limit == 0 || ms < limit {
			limit = ms
		}
	}
	return limit
}

func containsCSV(csv, value string) bool {
	for _, item := range strings.Split(csv, ",") {
		if strings.TrimSpace(item) == value {
			return true
		}
	}
	return false
}
