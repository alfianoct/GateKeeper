package models

import (
	"fmt"

	"github.com/judsenb/gatekeeper/internal/db"
	"github.com/judsenb/gatekeeper/internal/id"
)

type GroupMapping struct {
	ID              string `json:"id"`
	ExternalGroup   string `json:"external_group"`
	GatekeeperGroup string `json:"gatekeeper_group"`
	CreatedAt       string `json:"created_at"`
}

type GroupMappingStore struct {
	DB *db.DB
}

func (s *GroupMappingStore) List() ([]GroupMapping, error) {
	rows, err := s.DB.Query(`SELECT id, external_group, gatekeeper_group, created_at FROM group_mappings ORDER BY external_group`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var mappings []GroupMapping
	for rows.Next() {
		var m GroupMapping
		if err := rows.Scan(&m.ID, &m.ExternalGroup, &m.GatekeeperGroup, &m.CreatedAt); err != nil {
			return nil, err
		}
		mappings = append(mappings, m)
	}
	return mappings, rows.Err()
}

func (s *GroupMappingStore) Create(m *GroupMapping) error {
	if m.ID == "" {
		newID, err := id.New()
		if err != nil {
			return fmt.Errorf("generate mapping id: %w", err)
		}
		m.ID = newID
	}
	_, err := s.DB.Exec(`INSERT INTO group_mappings (id, external_group, gatekeeper_group) VALUES (?, ?, ?)`,
		m.ID, m.ExternalGroup, m.GatekeeperGroup)
	return err
}

func (s *GroupMappingStore) Delete(mappingID string) error {
	res, err := s.DB.Exec("DELETE FROM group_mappings WHERE id = ?", mappingID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("group mapping not found")
	}
	return nil
}

// ResolveGroups maps external IdP groups to GateKeeper groups. unmapped names pass through.
func (s *GroupMappingStore) ResolveGroups(externalGroups []string) ([]string, error) {
	mappings, err := s.List()
	if err != nil {
		return externalGroups, err
	}

	if len(mappings) == 0 {
		return externalGroups, nil
	}

	lookup := make(map[string]string)
	for _, m := range mappings {
		lookup[m.ExternalGroup] = m.GatekeeperGroup
	}

	seen := make(map[string]bool)
	var resolved []string
	for _, ext := range externalGroups {
		gk, ok := lookup[ext]
		if !ok {
			gk = ext
		}
		if !seen[gk] {
			seen[gk] = true
			resolved = append(resolved, gk)
		}
	}
	return resolved, nil
}
