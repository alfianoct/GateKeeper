package models_test

import (
	"testing"

	"github.com/judsenb/gatekeeper/internal/models"
	"github.com/judsenb/gatekeeper/internal/testutil"
)

func TestAuditStore_LogAndList(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.AuditStore{DB: db}

	entries := []models.AuditEntry{
		{Action: "login", UserID: "u1", Username: "alice", SourceIP: "10.0.0.1"},
		{Action: "logout", UserID: "u1", Username: "alice", SourceIP: "10.0.0.1"},
		{Action: "create_host", UserID: "u2", Username: "bob", TargetID: "h1", Target: "web-01"},
	}
	for i := range entries {
		if err := store.Log(&entries[i]); err != nil {
			t.Fatalf("log entry %d: %v", i, err)
		}
		if entries[i].ID == 0 {
			t.Fatalf("expected non-zero ID for entry %d", i)
		}
	}

	all, err := store.List("", 10, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(all))
	}
}

func TestAuditStore_ListByAction(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.AuditStore{DB: db}

	for _, action := range []string{"login", "login", "logout"} {
		if err := store.Log(&models.AuditEntry{Action: action, UserID: "u1", Username: "alice"}); err != nil {
			t.Fatalf("log %s: %v", action, err)
		}
	}

	logins, err := store.List("login", 10, 0)
	if err != nil {
		t.Fatalf("list login: %v", err)
	}
	if len(logins) != 2 {
		t.Fatalf("expected 2 login entries, got %d", len(logins))
	}
	for _, e := range logins {
		if e.Action != "login" {
			t.Fatalf("expected action login, got %s", e.Action)
		}
	}
}

func TestAuditStore_ListPagination(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.AuditStore{DB: db}

	for i := 0; i < 5; i++ {
		if err := store.Log(&models.AuditEntry{Action: "test", UserID: "u1", Username: "alice"}); err != nil {
			t.Fatalf("log %d: %v", i, err)
		}
	}

	page1, err := store.List("", 2, 0)
	if err != nil {
		t.Fatalf("list page1: %v", err)
	}
	if len(page1) != 2 {
		t.Fatalf("expected 2 in page1, got %d", len(page1))
	}

	page2, err := store.List("", 2, 2)
	if err != nil {
		t.Fatalf("list page2: %v", err)
	}
	if len(page2) != 2 {
		t.Fatalf("expected 2 in page2, got %d", len(page2))
	}

	if page1[0].ID == page2[0].ID {
		t.Fatal("page1 and page2 should not overlap")
	}
}

func TestAuditStore_ListRange(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.AuditStore{DB: db}

	entries := []models.AuditEntry{
		{Action: "early", UserID: "u1", Username: "alice"},
		{Action: "mid", UserID: "u1", Username: "alice"},
		{Action: "late", UserID: "u1", Username: "alice"},
	}
	for i := range entries {
		if err := store.Log(&entries[i]); err != nil {
			t.Fatalf("log %d: %v", i, err)
		}
	}

	// Override timestamps via direct SQL so we can test range filtering
	timestamps := []string{
		"2024-01-01T00:00:00Z",
		"2024-01-15T00:00:00Z",
		"2024-02-01T00:00:00Z",
	}
	for i, ts := range timestamps {
		if _, err := db.Exec("UPDATE audit_log SET timestamp = ? WHERE id = ?", ts, entries[i].ID); err != nil {
			t.Fatalf("update timestamp %d: %v", i, err)
		}
	}

	// Range covering Jan only should return the first two entries
	result, err := store.ListRange("2024-01-01T00:00:00Z", "2024-01-31T23:59:59Z", 10)
	if err != nil {
		t.Fatalf("list range: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 entries in Jan range, got %d", len(result))
	}

	// Range covering everything
	all, err := store.ListRange("2024-01-01T00:00:00Z", "2024-12-31T23:59:59Z", 10)
	if err != nil {
		t.Fatalf("list range all: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 entries in full range, got %d", len(all))
	}
}
