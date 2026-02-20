package models

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/judsenb/gatekeeper/internal/db"
	"github.com/judsenb/gatekeeper/internal/id"
)

// AccessWindow limits when hosts can be accessed. days use Go weekday numbering.
type AccessWindow struct {
	ID         string `json:"id"`
	EntityType string `json:"entity_type"` // "host" or "group"
	EntityID   string `json:"entity_id"`
	Days       string `json:"days"`       // e.g. "1-5"
	StartTime  string `json:"start_time"` // "09:00"
	EndTime    string `json:"end_time"`   // "17:00"
	Timezone   string `json:"timezone"`   // "UTC", "America/New_York"
}

type AccessWindowStore struct {
	DB *db.DB
}

func (s *AccessWindowStore) List(entityType, entityID string) ([]AccessWindow, error) {
	query := `SELECT id, entity_type, entity_id, days, start_time, end_time, timezone FROM access_windows WHERE 1=1`
	args := []any{}
	if entityType != "" {
		query += " AND entity_type = ?"
		args = append(args, entityType)
	}
	if entityID != "" {
		query += " AND entity_id = ?"
		args = append(args, entityID)
	}
	query += " ORDER BY entity_type, entity_id"
	rows, err := s.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []AccessWindow
	for rows.Next() {
		var w AccessWindow
		if err := rows.Scan(&w.ID, &w.EntityType, &w.EntityID, &w.Days, &w.StartTime, &w.EndTime, &w.Timezone); err != nil {
			return nil, err
		}
		list = append(list, w)
	}
	return list, rows.Err()
}

func (s *AccessWindowStore) Create(w *AccessWindow) error {
	if w.ID == "" {
		newID, err := id.Short()
		if err != nil {
			return fmt.Errorf("generate window id: %w", err)
		}
		w.ID = newID
	}
	_, err := s.DB.Exec(`
		INSERT INTO access_windows (id, entity_type, entity_id, days, start_time, end_time, timezone)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		w.ID, w.EntityType, w.EntityID, w.Days, w.StartTime, w.EndTime, w.Timezone)
	return err
}

func (s *AccessWindowStore) Delete(id string) error {
	_, err := s.DB.Exec("DELETE FROM access_windows WHERE id = ?", id)
	return err
}

// WithinWindow checks if now falls inside any applicable time window.
func (s *AccessWindowStore) WithinWindow(hostID string, groupNames []string, t time.Time) (bool, error) {
	windows, err := s.List("", "")
	if err != nil {
		return false, err
	}
	loc := time.UTC
	for _, w := range windows {
		applies := false
		if w.EntityType == "host" && w.EntityID == hostID {
			applies = true
		}
		for _, gname := range groupNames {
			if w.EntityType == "group" && w.EntityID == gname {
				applies = true
				break
			}
		}
		if !applies {
			continue
		}
		if w.Timezone != "" && w.Timezone != "UTC" {
			if l, err := time.LoadLocation(w.Timezone); err == nil {
				loc = l
			}
		}
		ct := t.In(loc)
		weekday := int(ct.Weekday()) // 0=Sun, 1=Mon, ...
		if !parseDays(w.Days).Contains(weekday) {
			continue
		}
		start, err1 := parseTime(w.StartTime)
		end, err2 := parseTime(w.EndTime)
		if err1 != nil || err2 != nil {
			continue
		}
		midnight := time.Date(ct.Year(), ct.Month(), ct.Day(), 0, 0, 0, 0, loc)
		windowStart := midnight.Add(start)
		windowEnd := midnight.Add(end)
		if !ct.Before(windowStart) && ct.Before(windowEnd) {
			return true, nil
		}
	}
	// no windows defined = no restriction, let them through
	hasWindow := false
	for _, w := range windows {
		if w.EntityType == "host" && w.EntityID == hostID {
			hasWindow = true
			break
		}
		for _, gname := range groupNames {
			if w.EntityType == "group" && w.EntityID == gname {
				hasWindow = true
				break
			}
		}
	}
	if !hasWindow {
		return true, nil
	}
	return false, nil
}

type daySet map[int]bool

func parseDays(s string) daySet {
	out := make(daySet)
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			ab := strings.SplitN(part, "-", 2)
			start, _ := strconv.Atoi(strings.TrimSpace(ab[0]))
			end, _ := strconv.Atoi(strings.TrimSpace(ab[1]))
			for i := start; i <= end; i++ {
				out[i] = true
			}
		} else {
			n, _ := strconv.Atoi(part)
			out[n] = true
		}
	}
	return out
}

func (d daySet) Contains(weekday int) bool {
	return d[weekday]
}

func parseTime(s string) (time.Duration, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return 0, strconv.ErrSyntax
	}
	h, _ := strconv.Atoi(strings.TrimSpace(parts[0]))
	m, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
	return time.Duration(h)*time.Hour + time.Duration(m)*time.Minute, nil
}
