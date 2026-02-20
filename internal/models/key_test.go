package models_test

import (
	"testing"

	"github.com/judsenb/gatekeeper/internal/models"
	"github.com/judsenb/gatekeeper/internal/testutil"
)

func TestKeyStore_CreateAndList(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.KeyStore{DB: database}

	keys, err := store.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected 0 keys, got %d", len(keys))
	}

	k := &models.SSHKey{
		Name:      "my-key",
		KeyType:   "rsa",
		PublicKey: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ test@host",
	}
	if err := store.Create(k); err != nil {
		t.Fatalf("create: %v", err)
	}
	if k.ID == "" {
		t.Fatal("expected auto-generated ID")
	}
	if k.Fingerprint == "" {
		t.Fatal("expected auto-computed fingerprint")
	}

	keys, err = store.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].Name != "my-key" {
		t.Fatalf("expected name=my-key, got %s", keys[0].Name)
	}
}

func TestKeyStore_GetByID(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.KeyStore{DB: database}

	k := &models.SSHKey{Name: "get-test", KeyType: "ed25519", PublicKey: "ssh-ed25519 AAAA test@host", PrivateKey: "-----BEGIN PRIVATE KEY-----"}
	if err := store.Create(k); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := store.GetByID(k.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.PrivateKey != "-----BEGIN PRIVATE KEY-----" {
		t.Fatal("expected private key to be returned from GetByID")
	}
}

func TestKeyStore_GetByUserID(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.KeyStore{DB: database}

	k1 := &models.SSHKey{Name: "user-key", KeyType: "rsa", PublicKey: "ssh-rsa AAA1 u@h", UserID: "user1"}
	k2 := &models.SSHKey{Name: "system-key", KeyType: "rsa", PublicKey: "ssh-rsa AAA2 sys@h", IsSystem: true}
	k3 := &models.SSHKey{Name: "other-key", KeyType: "rsa", PublicKey: "ssh-rsa AAA3 o@h", UserID: "user2"}
	store.Create(k1)
	store.Create(k2)
	store.Create(k3)

	keys, err := store.GetByUserID("user1")
	if err != nil {
		t.Fatalf("get by user: %v", err)
	}
	// should include user1's key + system key, not user2's
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys (user + system), got %d", len(keys))
	}
}

func TestKeyStore_Delete(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.KeyStore{DB: database}

	k := &models.SSHKey{Name: "deletable", KeyType: "rsa", PublicKey: "ssh-rsa AAAA del@h"}
	store.Create(k)

	if err := store.Delete(k.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	keys, _ := store.List()
	if len(keys) != 0 {
		t.Fatal("key still present after delete")
	}
}

func TestKeyStore_DeleteSystemKeyBlocked(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.KeyStore{DB: database}

	k := &models.SSHKey{Name: "sys", KeyType: "rsa", PublicKey: "ssh-rsa AAAA sys@h", IsSystem: true}
	store.Create(k)

	err := store.Delete(k.ID)
	if err == nil {
		t.Fatal("expected error when deleting system key")
	}
}

func TestKeyStore_TouchLastUsed(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.KeyStore{DB: database}

	k := &models.SSHKey{Name: "touch-test", KeyType: "rsa", PublicKey: "ssh-rsa AAAA touch@h"}
	store.Create(k)

	if err := store.TouchLastUsed(k.ID); err != nil {
		t.Fatalf("touch: %v", err)
	}

	got, _ := store.GetByID(k.ID)
	if got.LastUsedAt == nil {
		t.Fatal("expected last_used_at to be set after TouchLastUsed")
	}
}
