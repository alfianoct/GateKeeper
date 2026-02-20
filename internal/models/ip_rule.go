package models

import (
	"fmt"
	"net"
	"time"

	"github.com/judsenb/gatekeeper/internal/db"
	"github.com/judsenb/gatekeeper/internal/id"
)

type IPRule struct {
	ID          string `json:"id"`
	RuleType    string `json:"rule_type"` // "allow" or "deny"
	CIDR        string `json:"cidr"`      // e.g. "10.0.0.0/8" or "192.168.1.5/32"
	Scope       string `json:"scope"`     // "global" or "host"
	ScopeID     string `json:"scope_id"`  // host ID when scope=host
	Description string `json:"description"`
	CreatedAt   string `json:"created_at"`
	CreatedBy   string `json:"created_by"`
}

type IPRuleStore struct {
	DB *db.DB
}

func (s *IPRuleStore) List() ([]IPRule, error) {
	rows, err := s.DB.Query(`SELECT id, rule_type, cidr, scope, scope_id, description, created_at, created_by
		FROM ip_rules ORDER BY scope, rule_type, created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []IPRule
	for rows.Next() {
		var r IPRule
		if err := rows.Scan(&r.ID, &r.RuleType, &r.CIDR, &r.Scope, &r.ScopeID,
			&r.Description, &r.CreatedAt, &r.CreatedBy); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

func (s *IPRuleStore) Create(r *IPRule) error {
	if r.ID == "" {
		newID, err := id.New()
		if err != nil {
			return fmt.Errorf("generate id: %w", err)
		}
		r.ID = newID
	}
	if r.CreatedAt == "" {
		r.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}

	if _, _, err := net.ParseCIDR(r.CIDR); err != nil {
		// bare IP? slap a /32 or /128 on it
		ip := net.ParseIP(r.CIDR)
		if ip == nil {
			return fmt.Errorf("invalid CIDR or IP: %s", r.CIDR)
		}
		if ip.To4() != nil {
			r.CIDR = r.CIDR + "/32"
		} else {
			r.CIDR = r.CIDR + "/128"
		}
	}

	_, err := s.DB.Exec(`INSERT INTO ip_rules (id, rule_type, cidr, scope, scope_id, description, created_at, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.RuleType, r.CIDR, r.Scope, r.ScopeID, r.Description, r.CreatedAt, r.CreatedBy)
	return err
}

func (s *IPRuleStore) Delete(ruleID string) error {
	res, err := s.DB.Exec("DELETE FROM ip_rules WHERE id = ?", ruleID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("rule not found")
	}
	return nil
}

// Check runs deny-first, then allow-list. no rules = allow everything.
func (s *IPRuleStore) Check(remoteAddr, scope, scopeID string) (bool, string) {
	ip := extractIP(remoteAddr)
	if ip == nil {
		return true, ""
	}

	rules, err := s.listByScope(scope, scopeID)
	if err != nil {
		return true, ""
	}
	if len(rules) == 0 {
		return true, ""
	}

	for _, r := range rules {
		if r.RuleType != "deny" {
			continue
		}
		_, cidr, err := net.ParseCIDR(r.CIDR)
		if err != nil {
			continue
		}
		if cidr.Contains(ip) {
			return false, fmt.Sprintf("denied by rule: %s (%s)", r.Description, r.CIDR)
		}
	}

	// if there are allow rules, you better be on one of them
	hasAllow := false
	for _, r := range rules {
		if r.RuleType == "allow" {
			hasAllow = true
			break
		}
	}
	if !hasAllow {
		return true, ""
	}

	for _, r := range rules {
		if r.RuleType != "allow" {
			continue
		}
		_, cidr, err := net.ParseCIDR(r.CIDR)
		if err != nil {
			continue
		}
		if cidr.Contains(ip) {
			return true, ""
		}
	}

	return false, "not in IP allow list"
}

func (s *IPRuleStore) listByScope(scope, scopeID string) ([]IPRule, error) {
	query := `SELECT id, rule_type, cidr, scope, scope_id, description, created_at, created_by
		FROM ip_rules WHERE scope = ?`
	args := []any{scope}
	if scopeID != "" {
		query += " AND scope_id = ?"
		args = append(args, scopeID)
	}
	rows, err := s.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []IPRule
	for rows.Next() {
		var r IPRule
		if err := rows.Scan(&r.ID, &r.RuleType, &r.CIDR, &r.Scope, &r.ScopeID,
			&r.Description, &r.CreatedAt, &r.CreatedBy); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

func extractIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return net.ParseIP(remoteAddr)
	}
	return net.ParseIP(host)
}
