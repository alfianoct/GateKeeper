package models_test

import (
	"testing"
	"time"

	"github.com/judsenb/gatekeeper/internal/models"
	"github.com/judsenb/gatekeeper/internal/testutil"
)

func TestAccessRequestStore_CreateAndList(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.AccessRequestStore{DB: database}

	req := &models.AccessRequest{
		UserID:   "u1",
		Username: "alice",
		HostID:   "h1",
		Reason:   "need access",
	}
	if err := store.Create(req); err != nil {
		t.Fatalf("create: %v", err)
	}
	if req.ID == "" {
		t.Fatal("expected auto-generated ID")
	}
	if req.Status != "pending" {
		t.Fatalf("expected status=pending, got %s", req.Status)
	}

	list, err := store.ListPending(10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(list))
	}
}

func TestAccessRequestStore_GetByID(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.AccessRequestStore{DB: database}

	req := &models.AccessRequest{UserID: "u1", Username: "bob", HostID: "h2", Reason: "testing"}
	store.Create(req)

	got, err := store.GetByID(req.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Username != "bob" {
		t.Fatalf("expected username=bob, got %s", got.Username)
	}
}

func TestAccessRequestStore_Approve(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.AccessRequestStore{DB: database}

	req := &models.AccessRequest{UserID: "u1", Username: "charlie", HostID: "h3", Reason: "work"}
	store.Create(req)

	if err := store.Approve(req.ID, "admin"); err != nil {
		t.Fatalf("approve: %v", err)
	}

	got, _ := store.GetByID(req.ID)
	if got.Status != "approved" {
		t.Fatalf("expected approved, got %s", got.Status)
	}
	if got.DecidedBy != "admin" {
		t.Fatalf("expected decided_by=admin, got %s", got.DecidedBy)
	}

	pending, _ := store.ListPending(10)
	if len(pending) != 0 {
		t.Fatal("approved request should not appear in pending list")
	}
}

func TestAccessRequestStore_Reject(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.AccessRequestStore{DB: database}

	req := &models.AccessRequest{UserID: "u1", Username: "dave", HostID: "h4", Reason: "nope"}
	store.Create(req)

	if err := store.Reject(req.ID, "admin"); err != nil {
		t.Fatalf("reject: %v", err)
	}

	got, _ := store.GetByID(req.ID)
	if got.Status != "rejected" {
		t.Fatalf("expected rejected, got %s", got.Status)
	}
}

func TestAccessRequestStore_HasApprovedRequest(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.AccessRequestStore{DB: database}

	req := &models.AccessRequest{UserID: "u5", Username: "eve", HostID: "h5", Reason: "access pls"}
	store.Create(req)
	store.Approve(req.ID, "admin")

	has, err := store.HasApprovedRequest("u5", "h5", time.Hour)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !has {
		t.Fatal("expected HasApprovedRequest to return true")
	}

	has, _ = store.HasApprovedRequest("u5", "h999", time.Hour)
	if has {
		t.Fatal("should not have approval for different host")
	}
}
