package models_test

import (
	"testing"

	"github.com/judsenb/gatekeeper/internal/models"
	"github.com/judsenb/gatekeeper/internal/testutil"
)

func TestHostStore_CreateAndList(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.HostStore{DB: db}

	h := &models.Host{
		Name:     "web-01",
		Hostname: "10.0.0.1",
		Port:     2222,
		OS:       "linux",
		SSHUser:  "root",
	}
	if err := store.Create(h); err != nil {
		t.Fatalf("create: %v", err)
	}
	if h.ID == "" {
		t.Fatal("expected auto-generated ID")
	}

	hosts, err := store.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(hosts))
	}
	if hosts[0].Name != "web-01" {
		t.Fatalf("expected name web-01, got %s", hosts[0].Name)
	}
}

func TestHostStore_Defaults(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.HostStore{DB: db}

	h := &models.Host{Name: "default-host", Hostname: "10.0.0.2"}
	if err := store.Create(h); err != nil {
		t.Fatalf("create: %v", err)
	}
	if h.Port != 22 {
		t.Fatalf("expected default port 22, got %d", h.Port)
	}
	if h.SSHAuthMethod != "password" {
		t.Fatalf("expected default ssh_auth_method password, got %s", h.SSHAuthMethod)
	}
}

func TestHostStore_GetByID(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.HostStore{DB: db}

	h := &models.Host{
		Name:          "db-01",
		Hostname:      "10.0.1.5",
		Port:          5432,
		OS:            "linux",
		VLAN:          "db-vlan",
		Subnet:        "10.0.1.0/24",
		SSHUser:       "admin",
		SSHAuthMethod: "key",
		SSHKeyID:      "key-abc",
		RequireReason: true,
	}
	if err := store.Create(h); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := store.GetByID(h.ID)
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	if got.Name != "db-01" {
		t.Fatalf("expected name db-01, got %s", got.Name)
	}
	if got.Hostname != "10.0.1.5" {
		t.Fatalf("expected hostname 10.0.1.5, got %s", got.Hostname)
	}
	if got.Port != 5432 {
		t.Fatalf("expected port 5432, got %d", got.Port)
	}
	if got.VLAN != "db-vlan" {
		t.Fatalf("expected vlan db-vlan, got %s", got.VLAN)
	}
	if got.Subnet != "10.0.1.0/24" {
		t.Fatalf("expected subnet 10.0.1.0/24, got %s", got.Subnet)
	}
	if got.SSHAuthMethod != "key" {
		t.Fatalf("expected ssh_auth_method key, got %s", got.SSHAuthMethod)
	}
	if got.SSHKeyID != "key-abc" {
		t.Fatalf("expected ssh_key_id key-abc, got %s", got.SSHKeyID)
	}
	if !got.RequireReason {
		t.Fatal("expected require_reason true")
	}
	if got.CreatedAt == "" {
		t.Fatal("expected non-empty created_at")
	}
}

func TestHostStore_Update(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.HostStore{DB: db}

	h := &models.Host{Name: "old-name", Hostname: "10.0.0.1"}
	if err := store.Create(h); err != nil {
		t.Fatalf("create: %v", err)
	}

	h.Name = "new-name"
	h.Hostname = "10.0.0.2"
	if err := store.Update(h); err != nil {
		t.Fatalf("update: %v", err)
	}

	got, err := store.GetByID(h.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "new-name" {
		t.Fatalf("expected name new-name, got %s", got.Name)
	}
	if got.Hostname != "10.0.0.2" {
		t.Fatalf("expected hostname 10.0.0.2, got %s", got.Hostname)
	}
}

func TestHostStore_Delete(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.HostStore{DB: db}

	h := &models.Host{Name: "doomed", Hostname: "10.0.0.99"}
	if err := store.Create(h); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := store.Delete(h.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	hosts, err := store.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(hosts) != 0 {
		t.Fatalf("expected 0 hosts, got %d", len(hosts))
	}
}

func TestHostStore_DeleteNotFound(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.HostStore{DB: db}

	err := store.Delete("bogus-id")
	if err == nil {
		t.Fatal("expected error deleting nonexistent host")
	}
}

func TestHostStore_SetOnline(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.HostStore{DB: db}

	h := &models.Host{Name: "ontest", Hostname: "10.0.0.3"}
	if err := store.Create(h); err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := store.SetOnline(h.ID, true); err != nil {
		t.Fatalf("set online: %v", err)
	}

	got, err := store.GetByID(h.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.Online {
		t.Fatal("expected Online to be true")
	}
}

func TestHostStore_SetDisabled(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.HostStore{DB: db}

	h := &models.Host{Name: "distest", Hostname: "10.0.0.4"}
	if err := store.Create(h); err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := store.SetDisabled(h.ID, true); err != nil {
		t.Fatalf("set disabled: %v", err)
	}

	got, err := store.GetByID(h.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.Disabled {
		t.Fatal("expected Disabled to be true")
	}
}

func TestHostStore_Protocols(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.HostStore{DB: db}

	h := &models.Host{
		Name:      "multi-proto",
		Hostname:  "10.0.0.5",
		Protocols: []string{"SSH", "RDP"},
	}
	if err := store.Create(h); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := store.GetByID(h.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.Protocols) != 2 {
		t.Fatalf("expected 2 protocols, got %d", len(got.Protocols))
	}
	if got.Protocols[0] != "SSH" || got.Protocols[1] != "RDP" {
		t.Fatalf("expected [SSH RDP], got %v", got.Protocols)
	}
}
