package db_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/judsenb/gatekeeper/internal/db"
)

func TestMigrations_ApplyCleanly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	database, err := db.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() {
		database.Close()
		os.Remove(path)
	})

	if err := db.Migrate(database); err != nil {
		t.Fatalf("first migrate: %v", err)
	}

	var count int
	if err := database.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count); err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if count == 0 {
		t.Fatal("schema_migrations has no rows after migrate")
	}

	if err := db.Migrate(database); err != nil {
		t.Fatalf("idempotent migrate: %v", err)
	}
}

func TestMigrations_TablesExist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	database, err := db.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() {
		database.Close()
		os.Remove(path)
	})

	if err := db.Migrate(database); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	rows, err := database.DB.Query("SELECT name FROM sqlite_master WHERE type='table'")
	if err != nil {
		t.Fatalf("query sqlite_master: %v", err)
	}
	defer rows.Close()

	tables := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		tables[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows err: %v", err)
	}

	expected := []string{
		"users", "hosts", "sessions", "audit_log", "groups",
		"ssh_keys", "settings", "ip_rules", "mfa_pending",
		"password_history", "access_requests", "access_windows",
		"group_mappings", "schema_migrations",
	}
	for _, name := range expected {
		if !tables[name] {
			t.Errorf("expected table %q not found", name)
		}
	}
}
