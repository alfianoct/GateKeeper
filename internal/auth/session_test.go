package auth_test

import (
	"testing"
	"time"

	"github.com/judsenb/gatekeeper/internal/auth"
	"github.com/judsenb/gatekeeper/internal/testutil"
)

const testUserID = "user-test-001"

func createSessionStore(t *testing.T, dur time.Duration) (*auth.SessionStore, func()) {
	t.Helper()
	database := testutil.NewTestDB(t)
	_, err := database.DB.Exec(
		"INSERT INTO users (id, username) VALUES (?, ?)", testUserID, "testuser",
	)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	store := auth.NewSessionStore(database, dur)
	return store, func() {}
}

func TestSessionStore_CreateAndValidate(t *testing.T) {
	store, cleanup := createSessionStore(t, 24*time.Hour)
	defer cleanup()

	token, err := store.Create(testUserID, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	userID, err := store.Validate(token)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if userID != testUserID {
		t.Fatalf("expected user %q, got %q", testUserID, userID)
	}
}

func TestSessionStore_InvalidToken(t *testing.T) {
	store, cleanup := createSessionStore(t, 24*time.Hour)
	defer cleanup()

	_, err := store.Validate("bogus-token")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestSessionStore_Destroy(t *testing.T) {
	store, cleanup := createSessionStore(t, 24*time.Hour)
	defer cleanup()

	token, err := store.Create(testUserID, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := store.Destroy(token); err != nil {
		t.Fatalf("destroy: %v", err)
	}

	_, err = store.Validate(token)
	if err == nil {
		t.Fatal("expected error after destroy")
	}
}

func TestSessionStore_DestroyAllForUser(t *testing.T) {
	store, cleanup := createSessionStore(t, 24*time.Hour)
	defer cleanup()

	var tokens []string
	for i := 0; i < 3; i++ {
		tok, err := store.Create(testUserID, "127.0.0.1", "test-agent")
		if err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		tokens = append(tokens, tok)
	}

	if err := store.DestroyAllForUser(testUserID); err != nil {
		t.Fatalf("destroy all: %v", err)
	}

	for i, tok := range tokens {
		if _, err := store.Validate(tok); err == nil {
			t.Fatalf("token %d still valid after DestroyAllForUser", i)
		}
	}
}

func TestSessionStore_Expired(t *testing.T) {
	store, cleanup := createSessionStore(t, 1*time.Millisecond)
	defer cleanup()

	token, err := store.Create(testUserID, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	time.Sleep(5 * time.Millisecond)

	_, err = store.Validate(token)
	if err == nil {
		t.Fatal("expected error for expired session")
	}
}
