package testutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/judsenb/gatekeeper/internal/auth"
	"github.com/judsenb/gatekeeper/internal/db"
	"github.com/judsenb/gatekeeper/internal/models"
)

// TestContext carries test dependencies for API-level tests.
type TestContext struct {
	DB       *db.DB
	Users    *models.UserStore
	Settings *models.SettingStore
	Sessions *auth.SessionStore
}

// NewTestDB creates a temporary SQLite database with all migrations applied.
func NewTestDB(t *testing.T) *db.DB {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	database, err := db.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() {
		database.Close()
		os.Remove(path)
	})
	if err := db.Migrate(database); err != nil {
		t.Fatalf("migrate test db: %v", err)
	}
	return database
}
