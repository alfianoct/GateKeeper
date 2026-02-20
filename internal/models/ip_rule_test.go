package models_test

import (
	"testing"

	"github.com/judsenb/gatekeeper/internal/models"
	"github.com/judsenb/gatekeeper/internal/testutil"
)

func TestIPRuleStore_CreateAndList(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.IPRuleStore{DB: database}

	err := store.Create(&models.IPRule{
		RuleType:    "deny",
		CIDR:        "10.0.0.0/8",
		Scope:       "global",
		Description: "block private",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	rules, err := store.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].CIDR != "10.0.0.0/8" {
		t.Fatalf("expected CIDR 10.0.0.0/8, got %s", rules[0].CIDR)
	}
}

func TestIPRuleStore_BareIPNormalization(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.IPRuleStore{DB: database}

	r := &models.IPRule{
		RuleType: "deny",
		CIDR:     "10.0.0.1",
		Scope:    "global",
	}
	if err := store.Create(r); err != nil {
		t.Fatalf("create: %v", err)
	}
	if r.CIDR != "10.0.0.1/32" {
		t.Fatalf("expected 10.0.0.1/32, got %s", r.CIDR)
	}
}

func TestIPRuleStore_IPv6Normalization(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.IPRuleStore{DB: database}

	r := &models.IPRule{
		RuleType: "deny",
		CIDR:     "::1",
		Scope:    "global",
	}
	if err := store.Create(r); err != nil {
		t.Fatalf("create: %v", err)
	}
	if r.CIDR != "::1/128" {
		t.Fatalf("expected ::1/128, got %s", r.CIDR)
	}
}

func TestIPRuleStore_InvalidCIDR(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.IPRuleStore{DB: database}

	err := store.Create(&models.IPRule{
		RuleType: "deny",
		CIDR:     "notanip",
		Scope:    "global",
	})
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestIPRuleStore_Delete(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.IPRuleStore{DB: database}

	r := &models.IPRule{
		RuleType: "deny",
		CIDR:     "10.0.0.0/8",
		Scope:    "global",
	}
	if err := store.Create(r); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := store.Delete(r.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	rules, err := store.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("expected 0 rules, got %d", len(rules))
	}
}

func TestIPRuleStore_DeleteNotFound(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.IPRuleStore{DB: database}

	if err := store.Delete("nonexistent-id"); err == nil {
		t.Fatal("expected error deleting nonexistent rule")
	}
}

func TestIPRuleStore_Check_NoRules(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.IPRuleStore{DB: database}

	allowed, _ := store.Check("10.0.0.1:12345", "global", "")
	if !allowed {
		t.Fatal("expected allow with no rules")
	}
}

func TestIPRuleStore_Check_DenyBlock(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.IPRuleStore{DB: database}

	if err := store.Create(&models.IPRule{
		RuleType:    "deny",
		CIDR:        "10.0.0.0/8",
		Scope:       "global",
		Description: "block 10/8",
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	allowed, reason := store.Check("10.1.2.3:12345", "global", "")
	if allowed {
		t.Fatal("expected deny for 10.1.2.3")
	}
	if reason == "" {
		t.Fatal("expected non-empty reason")
	}
}

func TestIPRuleStore_Check_DenyPassthrough(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.IPRuleStore{DB: database}

	if err := store.Create(&models.IPRule{
		RuleType: "deny",
		CIDR:     "10.0.0.0/8",
		Scope:    "global",
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	allowed, _ := store.Check("192.168.1.1:12345", "global", "")
	if !allowed {
		t.Fatal("expected allow for 192.168.1.1")
	}
}

func TestIPRuleStore_Check_AllowList(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.IPRuleStore{DB: database}

	if err := store.Create(&models.IPRule{
		RuleType: "allow",
		CIDR:     "192.168.1.0/24",
		Scope:    "global",
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	allowed, _ := store.Check("192.168.1.5:12345", "global", "")
	if !allowed {
		t.Fatal("expected allow for 192.168.1.5")
	}

	allowed, _ = store.Check("10.0.0.1:12345", "global", "")
	if allowed {
		t.Fatal("expected deny for 10.0.0.1 (not in allow list)")
	}
}

func TestIPRuleStore_Check_DenyTakesPrecedence(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.IPRuleStore{DB: database}

	if err := store.Create(&models.IPRule{
		RuleType: "allow",
		CIDR:     "10.0.0.0/8",
		Scope:    "global",
	}); err != nil {
		t.Fatalf("create allow: %v", err)
	}
	if err := store.Create(&models.IPRule{
		RuleType:    "deny",
		CIDR:        "10.0.0.1/32",
		Scope:       "global",
		Description: "block specific host",
	}); err != nil {
		t.Fatalf("create deny: %v", err)
	}

	allowed, _ := store.Check("10.0.0.1:12345", "global", "")
	if allowed {
		t.Fatal("expected deny for 10.0.0.1 (deny takes precedence)")
	}

	allowed, _ = store.Check("10.0.0.2:12345", "global", "")
	if !allowed {
		t.Fatal("expected allow for 10.0.0.2")
	}
}
