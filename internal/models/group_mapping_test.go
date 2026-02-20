package models_test

import (
	"testing"

	"github.com/judsenb/gatekeeper/internal/models"
	"github.com/judsenb/gatekeeper/internal/testutil"
)

func TestGroupMappingStore_CreateAndList(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.GroupMappingStore{DB: database}

	list, _ := store.List()
	if len(list) != 0 {
		t.Fatalf("expected 0 mappings, got %d", len(list))
	}

	m := &models.GroupMapping{ExternalGroup: "okta-admins", GatekeeperGroup: "platform-admin"}
	if err := store.Create(m); err != nil {
		t.Fatalf("create: %v", err)
	}
	if m.ID == "" {
		t.Fatal("expected auto-generated ID")
	}

	list, _ = store.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 mapping, got %d", len(list))
	}
}

func TestGroupMappingStore_Delete(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.GroupMappingStore{DB: database}

	m := &models.GroupMapping{ExternalGroup: "ext", GatekeeperGroup: "gk"}
	store.Create(m)

	if err := store.Delete(m.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	list, _ := store.List()
	if len(list) != 0 {
		t.Fatal("mapping still present after delete")
	}
}

func TestGroupMappingStore_DeleteNotFound(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.GroupMappingStore{DB: database}

	if err := store.Delete("bogus"); err == nil {
		t.Fatal("expected error deleting non-existent mapping")
	}
}

func TestGroupMappingStore_ResolveGroups(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.GroupMappingStore{DB: database}

	store.Create(&models.GroupMapping{ExternalGroup: "ext-dev", GatekeeperGroup: "developers"})
	store.Create(&models.GroupMapping{ExternalGroup: "ext-ops", GatekeeperGroup: "operators"})

	resolved, err := store.ResolveGroups([]string{"ext-dev", "ext-ops", "unmapped-group"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	expected := map[string]bool{"developers": true, "operators": true, "unmapped-group": true}
	if len(resolved) != 3 {
		t.Fatalf("expected 3 resolved groups, got %d: %v", len(resolved), resolved)
	}
	for _, g := range resolved {
		if !expected[g] {
			t.Fatalf("unexpected group: %s", g)
		}
	}
}

func TestGroupMappingStore_ResolveNoMappings(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.GroupMappingStore{DB: database}

	input := []string{"group-a", "group-b"}
	resolved, _ := store.ResolveGroups(input)
	if len(resolved) != 2 || resolved[0] != "group-a" {
		t.Fatalf("no mappings should pass through: %v", resolved)
	}
}

func TestGroupMappingStore_ResolveDeduplicate(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.GroupMappingStore{DB: database}

	store.Create(&models.GroupMapping{ExternalGroup: "ext-a", GatekeeperGroup: "same"})
	store.Create(&models.GroupMapping{ExternalGroup: "ext-b", GatekeeperGroup: "same"})

	resolved, _ := store.ResolveGroups([]string{"ext-a", "ext-b"})
	if len(resolved) != 1 {
		t.Fatalf("expected deduplication to 1, got %d: %v", len(resolved), resolved)
	}
}
