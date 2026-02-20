package models_test

import (
	"testing"
	"time"

	"github.com/judsenb/gatekeeper/internal/db"
	"github.com/judsenb/gatekeeper/internal/models"
	"github.com/judsenb/gatekeeper/internal/testutil"
)

// seedHost creates a host so session FK constraints pass.
func seedHost(t *testing.T, database *db.DB, id, name string) {
	t.Helper()
	store := &models.HostStore{DB: database}
	if err := store.Create(&models.Host{ID: id, Name: name, Hostname: "10.0.0.1"}); err != nil {
		t.Fatalf("seed host %s: %v", id, err)
	}
}

func TestSessionStore_CreateAndList(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.SessionStore{DB: database}
	seedHost(t, database, "h1", "web-01")

	sess := &models.Session{
		UserID:   "u1",
		Username: "alice",
		HostID:   "h1",
		HostName: "web-01",
		HostAddr: "10.0.0.1:22",
		Protocol: "ssh",
	}
	if err := store.Create(sess); err != nil {
		t.Fatalf("create: %v", err)
	}
	if sess.ID == "" {
		t.Fatal("expected auto-generated ID")
	}
	if sess.ConnectedAt == "" {
		t.Fatal("expected ConnectedAt to be set")
	}

	active, err := store.ListActive()
	if err != nil {
		t.Fatalf("list active: %v", err)
	}
	if len(active) != 1 {
		t.Fatalf("expected 1 active session, got %d", len(active))
	}
	if active[0].Username != "alice" {
		t.Fatalf("expected username alice, got %s", active[0].Username)
	}
}

func TestSessionStore_GetByID(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.SessionStore{DB: database}
	seedHost(t, database, "h2", "db-01")

	sess := &models.Session{
		UserID:   "u1",
		Username: "bob",
		HostID:   "h2",
		HostName: "db-01",
		HostAddr: "10.0.0.2:22",
		Protocol: "ssh",
		Reason:   "maintenance",
	}
	if err := store.Create(sess); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := store.GetByID(sess.ID)
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	if got.Username != "bob" {
		t.Fatalf("expected username bob, got %s", got.Username)
	}
	if got.HostID != "h2" {
		t.Fatalf("expected host_id h2, got %s", got.HostID)
	}
	if got.Reason != "maintenance" {
		t.Fatalf("expected reason maintenance, got %s", got.Reason)
	}
	if got.ClosedAt != nil {
		t.Fatal("expected ClosedAt to be nil for active session")
	}
}

func TestSessionStore_Close(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.SessionStore{DB: database}
	seedHost(t, database, "h1", "web-01")

	sess := &models.Session{UserID: "u1", Username: "carol", HostID: "h1", HostName: "web-01", HostAddr: "10.0.0.1:22", Protocol: "ssh"}
	if err := store.Create(sess); err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := store.Close(sess.ID); err != nil {
		t.Fatalf("close: %v", err)
	}

	active, err := store.ListActive()
	if err != nil {
		t.Fatalf("list active: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("expected 0 active sessions, got %d", len(active))
	}

	history, err := store.ListHistory(10)
	if err != nil {
		t.Fatalf("list history: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("expected 1 history entry, got %d", len(history))
	}
	if history[0].ID != sess.ID {
		t.Fatalf("expected session id %s in history, got %s", sess.ID, history[0].ID)
	}
}

func TestSessionStore_GetActiveByHostID(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.SessionStore{DB: database}
	seedHost(t, database, "h1", "web-01")
	seedHost(t, database, "h2", "db-01")

	s1 := &models.Session{UserID: "u1", Username: "alice", HostID: "h1", HostName: "web-01", HostAddr: "10.0.0.1:22", Protocol: "ssh"}
	s2 := &models.Session{UserID: "u2", Username: "bob", HostID: "h2", HostName: "db-01", HostAddr: "10.0.0.2:22", Protocol: "ssh"}
	if err := store.Create(s1); err != nil {
		t.Fatalf("create s1: %v", err)
	}
	if err := store.Create(s2); err != nil {
		t.Fatalf("create s2: %v", err)
	}

	got, err := store.GetActiveByHostID("h1")
	if err != nil {
		t.Fatalf("get active by host id: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil session for h1")
	}
	if got.Username != "alice" {
		t.Fatalf("expected alice, got %s", got.Username)
	}

	got, err = store.GetActiveByHostID("h999")
	if err != nil {
		t.Fatalf("get active by host id: %v", err)
	}
	if got != nil {
		t.Fatal("expected nil for nonexistent host")
	}
}

func TestSessionStore_UpdateBytes(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.SessionStore{DB: database}
	seedHost(t, database, "h1", "web-01")

	sess := &models.Session{UserID: "u1", Username: "alice", HostID: "h1", HostName: "web-01", HostAddr: "10.0.0.1:22", Protocol: "ssh"}
	if err := store.Create(sess); err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := store.UpdateBytes(sess.ID, 1000, 500); err != nil {
		t.Fatalf("update bytes: %v", err)
	}

	got, err := store.GetByID(sess.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.BytesTX != 1000 {
		t.Fatalf("expected bytes_tx 1000, got %d", got.BytesTX)
	}
	if got.BytesRX != 500 {
		t.Fatalf("expected bytes_rx 500, got %d", got.BytesRX)
	}
}

func TestSessionStore_CleanupStale(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.SessionStore{DB: database}
	seedHost(t, database, "h1", "web-01")

	sess := &models.Session{UserID: "u1", Username: "stale", HostID: "h1", HostName: "web-01", HostAddr: "10.0.0.1:22", Protocol: "ssh"}
	if err := store.Create(sess); err != nil {
		t.Fatalf("create: %v", err)
	}

	oldTime := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
	if _, err := database.Exec("UPDATE sessions SET connected_at = ? WHERE id = ?", oldTime, sess.ID); err != nil {
		t.Fatalf("hack connected_at: %v", err)
	}

	cleaned, err := store.CleanupStale(1 * time.Hour)
	if err != nil {
		t.Fatalf("cleanup stale: %v", err)
	}
	if cleaned != 1 {
		t.Fatalf("expected 1 cleaned, got %d", cleaned)
	}

	active, _ := store.ListActive()
	if len(active) != 0 {
		t.Fatalf("expected 0 active after cleanup, got %d", len(active))
	}
}

func TestSessionStore_CountActiveByUserID(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.SessionStore{DB: database}
	seedHost(t, database, "h1", "web")
	seedHost(t, database, "h2", "db")

	for i := 0; i < 3; i++ {
		sess := &models.Session{UserID: "u1", Username: "alice", HostID: "h1", HostName: "web", HostAddr: "10.0.0.1:22", Protocol: "ssh"}
		if err := store.Create(sess); err != nil {
			t.Fatalf("create u1 session %d: %v", i, err)
		}
	}
	sess := &models.Session{UserID: "u2", Username: "bob", HostID: "h2", HostName: "db", HostAddr: "10.0.0.2:22", Protocol: "ssh"}
	if err := store.Create(sess); err != nil {
		t.Fatalf("create u2 session: %v", err)
	}

	n, err := store.CountActiveByUserID("u1")
	if err != nil {
		t.Fatalf("count u1: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 for u1, got %d", n)
	}

	n, err = store.CountActiveByUserID("u2")
	if err != nil {
		t.Fatalf("count u2: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 for u2, got %d", n)
	}
}

func TestSessionStore_ListHistory(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.SessionStore{DB: database}
	seedHost(t, database, "h1", "web")

	var ids []string
	for i := 0; i < 3; i++ {
		sess := &models.Session{UserID: "u1", Username: "alice", HostID: "h1", HostName: "web", HostAddr: "10.0.0.1:22", Protocol: "ssh"}
		if err := store.Create(sess); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		ids = append(ids, sess.ID)
	}

	for _, id := range ids {
		if err := store.Close(id); err != nil {
			t.Fatalf("close %s: %v", id, err)
		}
	}

	history, err := store.ListHistory(2)
	if err != nil {
		t.Fatalf("list history: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("expected 2, got %d", len(history))
	}
}
