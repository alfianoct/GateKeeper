package models_test

import (
	"database/sql"
	"testing"

	"github.com/judsenb/gatekeeper/internal/models"
	"github.com/judsenb/gatekeeper/internal/testutil"
)

func TestHostKeyStore_SaveAndGet(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.HostKeyStore{DB: database}

	if err := store.Save("h1", "ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5AAAA"); err != nil {
		t.Fatalf("save: %v", err)
	}

	pub, err := store.Get("h1", "ssh-ed25519")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if pub != "AAAAC3NzaC1lZDI1NTE5AAAA" {
		t.Fatalf("expected public key, got %s", pub)
	}
}

func TestHostKeyStore_SaveOverwrite(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.HostKeyStore{DB: database}

	store.Save("h1", "ssh-rsa", "old-key")
	store.Save("h1", "ssh-rsa", "new-key")

	pub, _ := store.Get("h1", "ssh-rsa")
	if pub != "new-key" {
		t.Fatalf("expected overwritten key, got %s", pub)
	}
}

func TestHostKeyStore_GetNotFound(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.HostKeyStore{DB: database}

	_, err := store.Get("nonexistent", "ssh-rsa")
	if err != sql.ErrNoRows {
		t.Fatalf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestHostKeyStore_DeleteByHostID(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.HostKeyStore{DB: database}

	store.Save("h1", "ssh-rsa", "key1")
	store.Save("h1", "ssh-ed25519", "key2")
	store.Save("h2", "ssh-rsa", "other-host-key")

	if err := store.DeleteByHostID("h1"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	_, err := store.Get("h1", "ssh-rsa")
	if err != sql.ErrNoRows {
		t.Fatal("expected h1 keys to be deleted")
	}

	pub, _ := store.Get("h2", "ssh-rsa")
	if pub != "other-host-key" {
		t.Fatal("h2 key should still exist")
	}
}
