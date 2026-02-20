package models_test

import (
	"testing"

	"github.com/judsenb/gatekeeper/internal/instance"
	"github.com/judsenb/gatekeeper/internal/models"
	"github.com/judsenb/gatekeeper/internal/testutil"
	"golang.org/x/crypto/bcrypt"
)

func init() { instance.Init() }

func TestUserStore_CreateAndList(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.UserStore{DB: db}

	u := &models.User{Username: "alice", DisplayName: "Alice A", Role: "admin", Groups: "ops"}
	if err := store.Create(u, "TestPass123!"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if u.ID == "" {
		t.Fatal("expected auto-generated ID")
	}

	users, err := store.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	if users[0].Username != "alice" {
		t.Fatalf("expected username alice, got %s", users[0].Username)
	}
}

func TestUserStore_GetByID(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.UserStore{DB: db}

	u := &models.User{Username: "bob", DisplayName: "Bob B", Role: "user", Groups: "dev"}
	if err := store.Create(u, "SecurePass1!"); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := store.GetByID(u.ID)
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	if got.Username != "bob" {
		t.Fatalf("expected username bob, got %s", got.Username)
	}
	if got.DisplayName != "Bob B" {
		t.Fatalf("expected display_name Bob B, got %s", got.DisplayName)
	}
	if got.Role != "user" {
		t.Fatalf("expected role user, got %s", got.Role)
	}
	if got.Groups != "dev" {
		t.Fatalf("expected groups dev, got %s", got.Groups)
	}
	if got.AuthProvider != "local" {
		t.Fatalf("expected auth_provider local, got %s", got.AuthProvider)
	}
	if got.PasswordHash == "" {
		t.Fatal("expected non-empty password hash")
	}
	if got.PasswordChangedAt == "" {
		t.Fatal("expected non-empty password_changed_at")
	}
}

func TestUserStore_GetByUsername(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.UserStore{DB: db}

	u := &models.User{Username: "carol", DisplayName: "Carol C"}
	if err := store.Create(u, "Pass1234!"); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := store.GetByUsername("carol")
	if err != nil {
		t.Fatalf("get by username: %v", err)
	}
	if got.ID != u.ID {
		t.Fatalf("expected id %s, got %s", u.ID, got.ID)
	}
}

func TestUserStore_Update(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.UserStore{DB: db}

	u := &models.User{Username: "dave", DisplayName: "Dave D", Role: "user"}
	if err := store.Create(u, "Pass1234!"); err != nil {
		t.Fatalf("create: %v", err)
	}

	u.DisplayName = "David D"
	u.Role = "admin"
	if err := store.Update(u); err != nil {
		t.Fatalf("update: %v", err)
	}

	got, err := store.GetByID(u.ID)
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	if got.DisplayName != "David D" {
		t.Fatalf("expected display_name David D, got %s", got.DisplayName)
	}
	if got.Role != "admin" {
		t.Fatalf("expected role admin, got %s", got.Role)
	}
}

func TestUserStore_Delete(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.UserStore{DB: db}

	u := &models.User{Username: "eve"}
	if err := store.Create(u, "Pass1234!"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := store.Delete(u.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	_, err := store.GetByID(u.ID)
	if err == nil {
		t.Fatal("expected error getting deleted user")
	}
}

func TestUserStore_DeleteNotFound(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.UserStore{DB: db}

	err := store.Delete("nonexistent-id")
	if err == nil {
		t.Fatal("expected error deleting nonexistent user")
	}
	if err.Error() != "user not found" {
		t.Fatalf("expected 'user not found', got %q", err.Error())
	}
}

func TestUserStore_CheckPassword(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.UserStore{DB: db}

	u := &models.User{Username: "frank"}
	if err := store.Create(u, "CorrectPass1!"); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := store.GetByID(u.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	if !store.CheckPassword(got, "CorrectPass1!") {
		t.Fatal("expected correct password to match")
	}
	if store.CheckPassword(got, "WrongPass999!") {
		t.Fatal("expected wrong password to not match")
	}
}

func TestUserStore_SetPassword(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.UserStore{DB: db}

	u := &models.User{Username: "grace"}
	if err := store.Create(u, "OldPass1!"); err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := store.SetPassword(u.ID, "NewPass1!"); err != nil {
		t.Fatalf("set password: %v", err)
	}

	got, err := store.GetByID(u.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if store.CheckPassword(got, "OldPass1!") {
		t.Fatal("old password should no longer match")
	}
	if !store.CheckPassword(got, "NewPass1!") {
		t.Fatal("new password should match")
	}
}

func TestUserStore_Count(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.UserStore{DB: db}

	n, err := store.Count()
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0, got %d", n)
	}

	if err := store.Create(&models.User{Username: "u1"}, "Pass1234!"); err != nil {
		t.Fatalf("create u1: %v", err)
	}
	n, err = store.Count()
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1, got %d", n)
	}

	if err := store.Create(&models.User{Username: "u2"}, "Pass1234!"); err != nil {
		t.Fatalf("create u2: %v", err)
	}
	n, err = store.Count()
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2, got %d", n)
	}
}

func TestUserStore_TouchLogin(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.UserStore{DB: db}

	u := &models.User{Username: "hank"}
	if err := store.Create(u, "Pass1234!"); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, _ := store.GetByID(u.ID)
	if got.LastLoginAt != nil {
		t.Fatal("expected nil LastLoginAt before TouchLogin")
	}

	store.TouchLogin(u.ID)

	got, _ = store.GetByID(u.ID)
	if got.LastLoginAt == nil {
		t.Fatal("expected non-nil LastLoginAt after TouchLogin")
	}
}

func TestUserStore_CreateOIDC(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.UserStore{DB: db}

	u := &models.User{
		Username:    "oidcuser",
		DisplayName: "OIDC User",
		Role:        "user",
		OIDCSubject: "sub-12345",
	}
	if err := store.CreateOIDC(u); err != nil {
		t.Fatalf("create oidc: %v", err)
	}
	if u.ID == "" {
		t.Fatal("expected auto-generated ID")
	}

	got, err := store.GetByID(u.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.AuthProvider != "oidc" {
		t.Fatalf("expected auth_provider oidc, got %s", got.AuthProvider)
	}
	if got.OIDCSubject != "sub-12345" {
		t.Fatalf("expected oidc_subject sub-12345, got %s", got.OIDCSubject)
	}
}

func TestUserStore_GetByOIDCSubject(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.UserStore{DB: db}

	u := &models.User{
		Username:    "oidclookup",
		OIDCSubject: "sub-99",
	}
	if err := store.CreateOIDC(u); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := store.GetByOIDCSubject("sub-99")
	if err != nil {
		t.Fatalf("get by oidc subject: %v", err)
	}
	if got.Username != "oidclookup" {
		t.Fatalf("expected username oidclookup, got %s", got.Username)
	}
}

func TestUserStore_CreateExternal(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.UserStore{DB: db}

	u := &models.User{
		Username:    "ldapuser",
		DisplayName: "LDAP User",
		Role:        "user",
		OIDCSubject: "cn=ldapuser,dc=example,dc=com",
	}
	if err := store.CreateExternal(u, "ldap"); err != nil {
		t.Fatalf("create external: %v", err)
	}

	got, err := store.GetByID(u.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.AuthProvider != "ldap" {
		t.Fatalf("expected auth_provider ldap, got %s", got.AuthProvider)
	}
}

func TestUserStore_MFA(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.UserStore{DB: db}

	u := &models.User{Username: "mfauser"}
	if err := store.Create(u, "Pass1234!"); err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := store.SetMFASecret(u.ID, "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatalf("set mfa secret: %v", err)
	}

	got, _ := store.GetByID(u.ID)
	if got.MFASecret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("expected mfa_secret to be set, got %q", got.MFASecret)
	}

	if err := store.EnableMFA(u.ID, "code1,code2,code3"); err != nil {
		t.Fatalf("enable mfa: %v", err)
	}

	got, _ = store.GetByID(u.ID)
	if !got.MFAEnabled {
		t.Fatal("expected mfa_enabled to be true")
	}
	if got.MFARecoveryCodes != "code1,code2,code3" {
		t.Fatalf("expected recovery codes, got %q", got.MFARecoveryCodes)
	}

	if err := store.DisableMFA(u.ID); err != nil {
		t.Fatalf("disable mfa: %v", err)
	}

	got, _ = store.GetByID(u.ID)
	if got.MFAEnabled {
		t.Fatal("expected mfa_enabled to be false after disable")
	}
	if got.MFASecret != "" {
		t.Fatalf("expected mfa_secret cleared, got %q", got.MFASecret)
	}
	if got.MFARecoveryCodes != "" {
		t.Fatalf("expected mfa_recovery_codes cleared, got %q", got.MFARecoveryCodes)
	}
}

func TestUserStore_PasswordHistory(t *testing.T) {
	db := testutil.NewTestDB(t)
	store := &models.UserStore{DB: db}

	u := &models.User{Username: "histuser"}
	if err := store.Create(u, "Pass1234!"); err != nil {
		t.Fatalf("create: %v", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte("OldPass1!"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt hash: %v", err)
	}
	if err := store.AddPasswordHistory(u.ID, string(hash)); err != nil {
		t.Fatalf("add password history: %v", err)
	}

	found, err := store.CheckPasswordHistory(u.ID, "OldPass1!", 5)
	if err != nil {
		t.Fatalf("check password history: %v", err)
	}
	if !found {
		t.Fatal("expected password to be found in history")
	}

	found, err = store.CheckPasswordHistory(u.ID, "NeverUsed1!", 5)
	if err != nil {
		t.Fatalf("check password history: %v", err)
	}
	if found {
		t.Fatal("expected password NOT to be found in history")
	}
}
