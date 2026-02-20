package models_test

import (
	"testing"
	"time"

	"github.com/judsenb/gatekeeper/internal/models"
	"github.com/judsenb/gatekeeper/internal/testutil"
)

func TestAccessWindowStore_CreateAndList(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.AccessWindowStore{DB: database}

	w := &models.AccessWindow{
		EntityType: "host",
		EntityID:   "h1",
		Days:       "1-5",
		StartTime:  "09:00",
		EndTime:    "17:00",
		Timezone:   "UTC",
	}
	if err := store.Create(w); err != nil {
		t.Fatalf("create: %v", err)
	}
	if w.ID == "" {
		t.Fatal("expected auto-generated ID")
	}

	list, err := store.List("", "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 window, got %d", len(list))
	}
}

func TestAccessWindowStore_ListFiltered(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.AccessWindowStore{DB: database}

	store.Create(&models.AccessWindow{EntityType: "host", EntityID: "h1", Days: "1-5", StartTime: "09:00", EndTime: "17:00", Timezone: "UTC"})
	store.Create(&models.AccessWindow{EntityType: "group", EntityID: "g1", Days: "0-6", StartTime: "00:00", EndTime: "23:59", Timezone: "UTC"})

	list, _ := store.List("host", "")
	if len(list) != 1 {
		t.Fatalf("expected 1 host window, got %d", len(list))
	}

	list, _ = store.List("", "g1")
	if len(list) != 1 {
		t.Fatalf("expected 1 group window, got %d", len(list))
	}
}

func TestAccessWindowStore_Delete(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.AccessWindowStore{DB: database}

	w := &models.AccessWindow{EntityType: "host", EntityID: "h1", Days: "1-5", StartTime: "09:00", EndTime: "17:00", Timezone: "UTC"}
	store.Create(w)

	if err := store.Delete(w.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	list, _ := store.List("", "")
	if len(list) != 0 {
		t.Fatal("window still present after delete")
	}
}

func TestAccessWindowStore_WithinWindow(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.AccessWindowStore{DB: database}

	store.Create(&models.AccessWindow{
		EntityType: "host",
		EntityID:   "h1",
		Days:       "1-5",
		StartTime:  "09:00",
		EndTime:    "17:00",
		Timezone:   "UTC",
	})

	// Wednesday 12:00 UTC should be within window (weekday=3, within 1-5)
	wed := time.Date(2025, 1, 8, 12, 0, 0, 0, time.UTC)
	ok, err := store.WithinWindow("h1", nil, wed)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !ok {
		t.Fatal("expected to be within window on Wed 12:00")
	}

	// Wednesday 20:00 UTC should be outside window
	wedLate := time.Date(2025, 1, 8, 20, 0, 0, 0, time.UTC)
	ok, _ = store.WithinWindow("h1", nil, wedLate)
	if ok {
		t.Fatal("expected to be outside window on Wed 20:00")
	}

	// Sunday should be outside window (weekday=0, not in 1-5)
	sun := time.Date(2025, 1, 5, 12, 0, 0, 0, time.UTC)
	ok, _ = store.WithinWindow("h1", nil, sun)
	if ok {
		t.Fatal("expected to be outside window on Sunday")
	}
}

func TestAccessWindowStore_NoWindowsAllowAll(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := &models.AccessWindowStore{DB: database}

	ok, err := store.WithinWindow("unwindowed-host", nil, time.Now())
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !ok {
		t.Fatal("no windows defined should allow access")
	}
}
