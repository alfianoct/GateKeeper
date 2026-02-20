package models_test

import (
	"sort"
	"testing"

	"github.com/judsenb/gatekeeper/internal/models"
	"github.com/judsenb/gatekeeper/internal/testutil"
)

func TestGroupStore_CreateAndList(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.GroupStore{DB: db}

	g := &models.Group{
		Name:        "engineers",
		Description: "Engineering team",
		Permissions: []string{"connect_hosts", "view_sessions"},
	}
	if err := store.Create(g); err != nil {
		t.Fatalf("create: %v", err)
	}
	if g.ID == "" {
		t.Fatal("expected auto-generated ID")
	}

	groups, err := store.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	if groups[0].Name != "engineers" {
		t.Fatalf("expected name engineers, got %s", groups[0].Name)
	}
}

func TestGroupStore_GetByID(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.GroupStore{DB: db}

	g := &models.Group{Name: "ops", Description: "Operations", Permissions: []string{"connect_hosts"}}
	if err := store.Create(g); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := store.GetByID(g.ID)
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	if got.Name != "ops" {
		t.Fatalf("expected name ops, got %s", got.Name)
	}
	if got.Description != "Operations" {
		t.Fatalf("expected description Operations, got %s", got.Description)
	}
}

func TestGroupStore_GetByName(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.GroupStore{DB: db}

	g := &models.Group{Name: "security", Permissions: []string{"view_audit"}}
	if err := store.Create(g); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := store.GetByName("security")
	if err != nil {
		t.Fatalf("get by name: %v", err)
	}
	if got.ID != g.ID {
		t.Fatalf("expected id %s, got %s", g.ID, got.ID)
	}
}

func TestGroupStore_Update(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.GroupStore{DB: db}

	g := &models.Group{Name: "old-name", Description: "old desc", Permissions: []string{"connect_hosts"}}
	if err := store.Create(g); err != nil {
		t.Fatalf("create: %v", err)
	}

	g.Name = "new-name"
	g.Description = "new desc"
	if err := store.Update(g); err != nil {
		t.Fatalf("update: %v", err)
	}

	got, err := store.GetByID(g.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "new-name" {
		t.Fatalf("expected name new-name, got %s", got.Name)
	}
	if got.Description != "new desc" {
		t.Fatalf("expected description new desc, got %s", got.Description)
	}
}

func TestGroupStore_Delete(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.GroupStore{DB: db}

	g := &models.Group{Name: "doomed"}
	if err := store.Create(g); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := store.Delete(g.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	groups, err := store.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(groups) != 0 {
		t.Fatalf("expected 0 groups, got %d", len(groups))
	}
}

func TestGroupStore_DeleteNotFound(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.GroupStore{DB: db}

	err := store.Delete("bogus-id")
	if err == nil {
		t.Fatal("expected error deleting nonexistent group")
	}
}

func TestGroupStore_HasPermission(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.GroupStore{DB: db}

	g := &models.Group{
		Name:        "devs",
		Permissions: []string{"connect_hosts", "view_sessions"},
	}
	if err := store.Create(g); err != nil {
		t.Fatalf("create: %v", err)
	}

	ok, err := store.HasPermission([]string{"devs"}, "connect_hosts")
	if err != nil {
		t.Fatalf("has permission: %v", err)
	}
	if !ok {
		t.Fatal("expected connect_hosts permission to be granted")
	}

	ok, err = store.HasPermission([]string{"devs"}, "manage_users")
	if err != nil {
		t.Fatalf("has permission: %v", err)
	}
	if ok {
		t.Fatal("expected manage_users permission to be denied")
	}
}

func TestGroupStore_HasPermission_NoGroups(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.GroupStore{DB: db}

	ok, err := store.HasPermission([]string{}, "anything")
	if err != nil {
		t.Fatalf("has permission: %v", err)
	}
	if ok {
		t.Fatal("expected false for empty groups")
	}
}

func TestGroupStore_EffectivePermissions(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.GroupStore{DB: db}

	if err := store.Create(&models.Group{
		Name:        "group-a",
		Permissions: []string{"connect_hosts", "view_sessions"},
	}); err != nil {
		t.Fatalf("create group-a: %v", err)
	}
	if err := store.Create(&models.Group{
		Name:        "group-b",
		Permissions: []string{"view_sessions", "view_audit"},
	}); err != nil {
		t.Fatalf("create group-b: %v", err)
	}

	perms, err := store.EffectivePermissions([]string{"group-a", "group-b"})
	if err != nil {
		t.Fatalf("effective permissions: %v", err)
	}

	sort.Strings(perms)
	expected := []string{"connect_hosts", "view_audit", "view_sessions"}
	if len(perms) != len(expected) {
		t.Fatalf("expected %d permissions, got %d: %v", len(expected), len(perms), perms)
	}
	for i, p := range expected {
		if perms[i] != p {
			t.Fatalf("expected %s at index %d, got %s", p, i, perms[i])
		}
	}
}

func TestGroupStore_CheckAccess_Wildcard(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.GroupStore{DB: db}

	if err := store.Create(&models.Group{
		Name:         "admins",
		AllowedHosts: "*",
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	ok, err := store.CheckAccess([]string{"admins"}, "any-host-id")
	if err != nil {
		t.Fatalf("check access: %v", err)
	}
	if !ok {
		t.Fatal("expected wildcard to allow any host")
	}
}

func TestGroupStore_CheckAccess_Specific(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.GroupStore{DB: db}

	if err := store.Create(&models.Group{
		Name:         "restricted",
		AllowedHosts: "host1,host2",
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	ok, err := store.CheckAccess([]string{"restricted"}, "host1")
	if err != nil {
		t.Fatalf("check access: %v", err)
	}
	if !ok {
		t.Fatal("expected access to host1")
	}

	ok, err = store.CheckAccess([]string{"restricted"}, "host3")
	if err != nil {
		t.Fatalf("check access: %v", err)
	}
	if ok {
		t.Fatal("expected no access to host3")
	}
}

func TestGroupStore_CheckAccess_NoGroups(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.GroupStore{DB: db}

	// No groups in DB at all = legacy fallback, allow everything
	ok, err := store.CheckAccess([]string{}, "any-host")
	if err != nil {
		t.Fatalf("check access: %v", err)
	}
	if !ok {
		t.Fatal("expected legacy fallback to allow access when no groups exist")
	}
}

func TestGroupStore_MaxSessionsForUser(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.GroupStore{DB: db}

	if err := store.Create(&models.Group{
		Name:        "A",
		MaxSessions: 5,
	}); err != nil {
		t.Fatalf("create A: %v", err)
	}
	if err := store.Create(&models.Group{
		Name:        "B",
		MaxSessions: 3,
	}); err != nil {
		t.Fatalf("create B: %v", err)
	}

	limit := store.MaxSessionsForUser([]string{"A", "B"})
	if limit != 3 {
		t.Fatalf("expected lowest non-zero limit 3, got %d", limit)
	}
}
