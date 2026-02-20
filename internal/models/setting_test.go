package models_test

import (
	"crypto/rand"
	"strings"
	"testing"

	"github.com/judsenb/gatekeeper/internal/models"
	"github.com/judsenb/gatekeeper/internal/testutil"
)

func TestSettingStore_GetDefault(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.SettingStore{DB: database}

	got := store.Get("nonexistent_key", "fallback")
	if got != "fallback" {
		t.Fatalf("expected default %q, got %q", "fallback", got)
	}
}

func TestSettingStore_SetAndGet(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.SettingStore{DB: database}

	if err := store.Set("auth_mode", "local"); err != nil {
		t.Fatalf("set: %v", err)
	}

	got := store.Get("auth_mode", "")
	if got != "local" {
		t.Fatalf("expected %q, got %q", "local", got)
	}
}

func TestSettingStore_EncryptedRoundTrip(t *testing.T) {
	database := testutil.NewTestDB(t)

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}

	store := &models.SettingStore{DB: database, EncryptionKey: key}

	if err := store.Set("oidc_client_secret", "my-secret"); err != nil {
		t.Fatalf("set: %v", err)
	}

	got := store.Get("oidc_client_secret", "")
	if got != "my-secret" {
		t.Fatalf("expected %q, got %q", "my-secret", got)
	}

	var raw string
	if err := database.QueryRow("SELECT value FROM settings WHERE key = ?", "oidc_client_secret").Scan(&raw); err != nil {
		t.Fatalf("raw query: %v", err)
	}
	if !strings.HasPrefix(raw, "enc:v1:") {
		t.Fatalf("stored value should start with enc:v1:, got %q", raw)
	}
}

func TestSettingStore_OverwriteSetting(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.SettingStore{DB: database}

	if err := store.Set("auth_mode", "local"); err != nil {
		t.Fatalf("set first: %v", err)
	}
	if err := store.Set("auth_mode", "oidc"); err != nil {
		t.Fatalf("set second: %v", err)
	}

	got := store.Get("auth_mode", "")
	if got != "oidc" {
		t.Fatalf("expected %q, got %q", "oidc", got)
	}
}
