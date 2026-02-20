package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/judsenb/gatekeeper/internal/api"
	"github.com/judsenb/gatekeeper/internal/auth"
	"github.com/judsenb/gatekeeper/internal/config"
	"github.com/judsenb/gatekeeper/internal/instance"
	"github.com/judsenb/gatekeeper/internal/models"
	sshpkg "github.com/judsenb/gatekeeper/internal/ssh"
	"github.com/judsenb/gatekeeper/internal/testutil"
	"github.com/judsenb/gatekeeper/web"
)

func init() {
	instance.Init()
}

const testAdminPassword = "TestPassword123!"

func setupTestRouter(t *testing.T) (http.Handler, *testutil.TestContext) {
	t.Helper()
	database := testutil.NewTestDB(t)

	users := &models.UserStore{DB: database}

	// create an admin user with a known password so we can actually log in
	admin := &models.User{
		Username:     "admin",
		DisplayName:  "Administrator",
		Role:         "platform-admin",
		Groups:       "platform-admin",
		AuthProvider: "local",
	}
	if err := users.Create(admin, testAdminPassword); err != nil {
		t.Fatalf("create test admin: %v", err)
	}

	cfg := &config.Config{
		Server: config.ServerConfig{
			Listen:         ":0",
			HTTPRedirect:   ":0",
			DeploymentMode: "single",
			TLSCert:        "fake",
		},
		Database: config.DatabaseConfig{Driver: "sqlite", Path: "test.db"},
		SSH:      config.SSHConfig{DefaultPort: 22, ConnectTimeout: "10s", KeepaliveInterval: "30s"},
		Audit:    config.AuditConfig{RetentionDays: 90, RecordingPath: t.TempDir()},
		Auth:     config.AuthConfig{SessionDuration: "24h"},
		Health:   config.HealthConfig{CheckInterval: "60s", Timeout: "5s"},
	}

	sshMgr := sshpkg.NewSessionManager()
	router := api.NewRouter(database, cfg, web.Assets, sshMgr, nil)

	settings := &models.SettingStore{DB: database}
	sessions := auth.NewSessionStore(database, 24*time.Hour)

	return router, &testutil.TestContext{
		DB:       database,
		Users:    users,
		Settings: settings,
		Sessions: sessions,
	}
}

func TestHealth_Liveness(t *testing.T) {
	router, _ := setupTestRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var body map[string]any
	json.NewDecoder(w.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Fatalf("expected status=ok, got %v", body["status"])
	}
}

func TestHealth_Readiness(t *testing.T) {
	router, _ := setupTestRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestLogin_ValidCredentials(t *testing.T) {
	router, _ := setupTestRouter(t)

	body, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": testAdminPassword,
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		respBody, _ := io.ReadAll(w.Body)
		t.Fatalf("expected 200, got %d: %s", w.Code, respBody)
	}

	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "gk_session" && c.Value != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected gk_session cookie to be set")
	}
}

func TestLogin_BadCredentials(t *testing.T) {
	router, _ := setupTestRouter(t)

	body, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": "wrongpassword",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestLogin_EmptyBody(t *testing.T) {
	router, _ := setupTestRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestAPI_Unauthenticated(t *testing.T) {
	router, _ := setupTestRouter(t)

	endpoints := []string{"/api/me", "/api/hosts", "/api/users", "/api/groups", "/api/settings"}
	for _, ep := range endpoints {
		req := httptest.NewRequest(http.MethodGet, ep, nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: expected 401, got %d", ep, w.Code)
		}
	}
}

func TestAPI_AuthenticatedGetMe(t *testing.T) {
	router, ctx := setupTestRouter(t)

	token := loginAsAdmin(t, router)

	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	req.AddCookie(&http.Cookie{Name: "gk_session", Value: token})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var body map[string]any
	json.NewDecoder(w.Body).Decode(&body)
	if body["username"] != "admin" {
		t.Fatalf("expected username=admin, got %v", body["username"])
	}
	if body["role"] != "platform-admin" {
		t.Fatalf("expected role=platform-admin, got %v", body["role"])
	}
	if body["instance_id"] == nil || body["instance_id"] == "" {
		t.Fatal("expected instance_id to be set")
	}
	_ = ctx
}

func TestAPI_ListHosts(t *testing.T) {
	router, _ := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	req := httptest.NewRequest(http.MethodGet, "/api/hosts", nil)
	req.AddCookie(&http.Cookie{Name: "gk_session", Value: token})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestAPI_CreateHost(t *testing.T) {
	router, _ := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	body, _ := json.Marshal(map[string]any{
		"name":     "Test Host",
		"hostname": "10.0.0.1",
		"port":     22,
		"os":       "linux",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/hosts", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "gk_session", Value: token})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		respBody, _ := io.ReadAll(w.Body)
		t.Fatalf("expected 200/201, got %d: %s", w.Code, respBody)
	}
}

func TestAPI_AuthProviders(t *testing.T) {
	router, _ := setupTestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/auth/providers", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var body map[string]any
	json.NewDecoder(w.Body).Decode(&body)
	if body["local"] != true {
		t.Fatal("expected local=true by default")
	}
}

func TestAPI_Logout(t *testing.T) {
	router, _ := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	// logout
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "gk_session", Value: token})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}

	// token should be invalid now
	req = httptest.NewRequest(http.MethodGet, "/api/me", nil)
	req.AddCookie(&http.Cookie{Name: "gk_session", Value: token})
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after logout, got %d", w.Code)
	}
}

func TestAPI_BearerTokenAuth(t *testing.T) {
	router, _ := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with Bearer token, got %d", w.Code)
	}
}

// loginAsAdmin logs in as the bootstrap admin and returns the session token.
func loginAsAdmin(t *testing.T, router http.Handler) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": testAdminPassword,
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		respBody, _ := io.ReadAll(w.Body)
		t.Fatalf("login failed: %d %s", w.Code, respBody)
	}

	for _, c := range w.Result().Cookies() {
		if c.Name == "gk_session" {
			return c.Value
		}
	}
	t.Fatal("no gk_session cookie in login response")
	return ""
}

func createUserAndLogin(t *testing.T, router http.Handler, ctx *testutil.TestContext, username, password, role string) string {
	t.Helper()
	u := &models.User{Username: username, DisplayName: username, Role: role, AuthProvider: "local"}
	if err := ctx.Users.Create(u, password); err != nil {
		t.Fatalf("create user %s: %v", username, err)
	}
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("login as %s failed: %d", username, w.Code)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == "gk_session" {
			return c.Value
		}
	}
	t.Fatalf("no session cookie for %s", username)
	return ""
}

func authGet(t *testing.T, router http.Handler, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.AddCookie(&http.Cookie{Name: "gk_session", Value: token})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func authRequest(t *testing.T, router http.Handler, method, path, token string, payload any) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader
	if payload != nil {
		b, _ := json.Marshal(payload)
		body = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, body)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "gk_session", Value: token})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func decodeResponse(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.NewDecoder(w.Body).Decode(&m); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, w.Body.String())
	}
	return m
}

// ---------------------------------------------------------------------------
// User CRUD
// ---------------------------------------------------------------------------

func TestAPI_ListUsers(t *testing.T) {
	router, _ := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	w := authGet(t, router, "/api/users", token)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var users []map[string]any
	if err := json.NewDecoder(w.Body).Decode(&users); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(users) == 0 {
		t.Fatal("expected at least one user (admin)")
	}
}

func TestAPI_CreateUser(t *testing.T) {
	router, _ := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	w := authRequest(t, router, http.MethodPost, "/api/users", token, map[string]string{
		"username":     "newuser",
		"password":     "NewPassword123!",
		"role":         "user",
		"display_name": "New User",
	})
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("expected 200/201, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeResponse(t, w)
	if resp["username"] != "newuser" {
		t.Fatalf("expected username=newuser, got %v", resp["username"])
	}
	if resp["id"] == nil || resp["id"] == "" {
		t.Fatal("expected id in response")
	}
}

func TestAPI_UpdateUser(t *testing.T) {
	router, ctx := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	u := &models.User{Username: "editme", DisplayName: "Edit Me", Role: "user", AuthProvider: "local"}
	if err := ctx.Users.Create(u, "EditPass123!"); err != nil {
		t.Fatalf("create user: %v", err)
	}

	w := authRequest(t, router, http.MethodPut, "/api/users/"+u.ID, token, map[string]string{
		"display_name": "Updated",
		"role":         "user",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeResponse(t, w)
	if resp["display_name"] != "Updated" {
		t.Fatalf("expected display_name=Updated, got %v", resp["display_name"])
	}
}

func TestAPI_DeleteUser(t *testing.T) {
	router, ctx := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	u := &models.User{Username: "deleteme", DisplayName: "Delete Me", Role: "user", AuthProvider: "local"}
	if err := ctx.Users.Create(u, "DelPass123!"); err != nil {
		t.Fatalf("create user: %v", err)
	}

	w := authRequest(t, router, http.MethodDelete, "/api/users/"+u.ID, token, nil)
	if w.Code != http.StatusNoContent && w.Code != http.StatusOK {
		t.Fatalf("expected 200/204, got %d: %s", w.Code, w.Body.String())
	}

	w2 := authGet(t, router, "/api/users", token)
	var users []map[string]any
	json.NewDecoder(w2.Body).Decode(&users)
	for _, usr := range users {
		if usr["username"] == "deleteme" {
			t.Fatal("deleted user still appears in list")
		}
	}
}

// ---------------------------------------------------------------------------
// Group CRUD
// ---------------------------------------------------------------------------

func TestAPI_ListGroups(t *testing.T) {
	router, _ := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	w := authGet(t, router, "/api/groups", token)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestAPI_CreateGroup(t *testing.T) {
	router, _ := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	w := authRequest(t, router, http.MethodPost, "/api/groups", token, map[string]any{
		"name":        "testers",
		"description": "Test group",
		"permissions": []string{"connect_hosts", "view_sessions"},
	})
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("expected 200/201, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeResponse(t, w)
	if resp["name"] != "testers" {
		t.Fatalf("expected name=testers, got %v", resp["name"])
	}
	if resp["id"] == nil || resp["id"] == "" {
		t.Fatal("expected id in response")
	}
}

func TestAPI_DeleteGroup(t *testing.T) {
	router, _ := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	w := authRequest(t, router, http.MethodPost, "/api/groups", token, map[string]any{
		"name":        "ephemeral",
		"description": "Will be deleted",
		"permissions": []string{"connect_hosts"},
	})
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("create group: expected 200/201, got %d", w.Code)
	}
	created := decodeResponse(t, w)
	groupID, _ := created["id"].(string)

	w2 := authRequest(t, router, http.MethodDelete, "/api/groups/"+groupID, token, nil)
	if w2.Code != http.StatusNoContent && w2.Code != http.StatusOK {
		t.Fatalf("expected 200/204, got %d: %s", w2.Code, w2.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Host operations
// ---------------------------------------------------------------------------

func createTestHost(t *testing.T, router http.Handler, token string) string {
	t.Helper()
	w := authRequest(t, router, http.MethodPost, "/api/hosts", token, map[string]any{
		"name":     "TestHost",
		"hostname": "10.0.0.99",
		"port":     22,
		"os":       "linux",
	})
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("create host: expected 200/201, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	id, _ := resp["id"].(string)
	if id == "" {
		t.Fatal("expected host id in response")
	}
	return id
}

func TestAPI_UpdateHost(t *testing.T) {
	router, _ := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	hostID := createTestHost(t, router, token)

	w := authRequest(t, router, http.MethodPut, "/api/hosts/"+hostID, token, map[string]any{
		"name":     "UpdatedHost",
		"hostname": "10.0.0.99",
		"port":     22,
		"os":       "linux",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeResponse(t, w)
	if resp["name"] != "UpdatedHost" {
		t.Fatalf("expected name=UpdatedHost, got %v", resp["name"])
	}
}

func TestAPI_DeleteHost(t *testing.T) {
	router, _ := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	hostID := createTestHost(t, router, token)

	w := authRequest(t, router, http.MethodDelete, "/api/hosts/"+hostID, token, nil)
	if w.Code != http.StatusNoContent && w.Code != http.StatusOK {
		t.Fatalf("expected 200/204, got %d: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

func TestAPI_GetSettings(t *testing.T) {
	router, _ := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	w := authGet(t, router, "/api/settings", token)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

func TestAPI_GetDashboard(t *testing.T) {
	router, _ := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	w := authGet(t, router, "/api/dashboard", token)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeResponse(t, w)
	if resp["instance_id"] == nil {
		t.Fatal("expected instance_id in dashboard response")
	}
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

func TestAPI_GetAuditLog(t *testing.T) {
	router, _ := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	w := authGet(t, router, "/api/audit", token)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// IP Rules
// ---------------------------------------------------------------------------

func TestAPI_IPRules_CRUD(t *testing.T) {
	router, _ := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	// create a deny rule for an IP that doesn't match the test client,
	// so the GlobalIPFilter won't block subsequent requests
	w := authRequest(t, router, http.MethodPost, "/api/ip-rules", token, map[string]any{
		"rule_type":   "deny",
		"cidr":        "10.99.99.0/24",
		"scope":       "global",
		"description": "test deny rule",
	})
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("create ip-rule: expected 200/201, got %d: %s", w.Code, w.Body.String())
	}
	created := decodeResponse(t, w)
	ruleID, _ := created["id"].(string)
	if ruleID == "" {
		t.Fatal("expected rule id in response")
	}

	// list and verify presence
	w2 := authGet(t, router, "/api/ip-rules", token)
	if w2.Code != http.StatusOK {
		t.Fatalf("list ip-rules: expected 200, got %d", w2.Code)
	}
	var rules []map[string]any
	json.NewDecoder(w2.Body).Decode(&rules)
	found := false
	for _, r := range rules {
		if r["id"] == ruleID {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("created IP rule not found in list")
	}

	// delete
	w3 := authRequest(t, router, http.MethodDelete, "/api/ip-rules/"+ruleID, token, nil)
	if w3.Code != http.StatusOK && w3.Code != http.StatusNoContent {
		t.Fatalf("delete ip-rule: expected 200/204, got %d: %s", w3.Code, w3.Body.String())
	}

	// verify gone
	w4 := authGet(t, router, "/api/ip-rules", token)
	var rulesAfter []map[string]any
	json.NewDecoder(w4.Body).Decode(&rulesAfter)
	for _, r := range rulesAfter {
		if r["id"] == ruleID {
			t.Fatal("deleted IP rule still in list")
		}
	}
}

// ---------------------------------------------------------------------------
// MFA
// ---------------------------------------------------------------------------

func TestAPI_MFA_Status(t *testing.T) {
	router, _ := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	w := authGet(t, router, "/api/me/mfa", token)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	resp := decodeResponse(t, w)
	if resp["mfa_enabled"] != false {
		t.Fatalf("expected mfa_enabled=false, got %v", resp["mfa_enabled"])
	}
}

// ---------------------------------------------------------------------------
// Permission enforcement
// ---------------------------------------------------------------------------

func TestAPI_RegularUserDeniedAdminEndpoints(t *testing.T) {
	router, ctx := setupTestRouter(t)

	token := createUserAndLogin(t, router, ctx, "regularjoe", "RegularPass123!", "user")

	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/users"},
		{http.MethodGet, "/api/settings"},
	}
	for _, ep := range endpoints {
		w := authRequest(t, router, ep.method, ep.path, token, nil)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s: expected 403, got %d", ep.method, ep.path, w.Code)
		}
	}
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

func TestAPI_ListActiveSessions(t *testing.T) {
	router, _ := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	w := authGet(t, router, "/api/sessions", token)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var sessions []map[string]any
	json.NewDecoder(w.Body).Decode(&sessions)
	if sessions == nil {
		t.Fatal("expected non-nil sessions array")
	}
}

func TestAPI_ListSessionHistory(t *testing.T) {
	router, _ := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	w := authGet(t, router, "/api/sessions/history", token)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

func TestAPI_Keys_CRUD(t *testing.T) {
	router, _ := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	// list (empty)
	w := authGet(t, router, "/api/keys", token)
	if w.Code != http.StatusOK {
		t.Fatalf("list keys: expected 200, got %d", w.Code)
	}

	// create
	w = authRequest(t, router, http.MethodPost, "/api/keys", token, map[string]string{
		"name":       "test-key",
		"public_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ test@test",
	})
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("create key: expected 200/201, got %d: %s", w.Code, w.Body.String())
	}
	created := decodeResponse(t, w)
	keyID, _ := created["id"].(string)
	if keyID == "" {
		t.Fatal("expected key id in response")
	}

	// delete
	w = authRequest(t, router, http.MethodDelete, "/api/keys/"+keyID, token, nil)
	if w.Code != http.StatusNoContent && w.Code != http.StatusOK {
		t.Fatalf("delete key: expected 200/204, got %d: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Host Toggle Disabled
// ---------------------------------------------------------------------------

func TestAPI_ToggleHostDisabled(t *testing.T) {
	router, _ := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	hostID := createTestHost(t, router, token)

	w := authRequest(t, router, http.MethodPost, "/api/hosts/"+hostID+"/toggle-disabled", token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("toggle disabled: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	resp := decodeResponse(t, w)
	if resp["disabled"] != true {
		t.Fatalf("expected disabled=true, got %v", resp["disabled"])
	}

	// toggle back
	w = authRequest(t, router, http.MethodPost, "/api/hosts/"+hostID+"/toggle-disabled", token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("toggle back: expected 200, got %d", w.Code)
	}
	resp = decodeResponse(t, w)
	if resp["disabled"] != false {
		t.Fatalf("expected disabled=false, got %v", resp["disabled"])
	}
}

// ---------------------------------------------------------------------------
// Get Host + Active Session
// ---------------------------------------------------------------------------

func TestAPI_GetHost(t *testing.T) {
	router, _ := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	hostID := createTestHost(t, router, token)

	w := authGet(t, router, "/api/hosts/"+hostID, token)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	resp := decodeResponse(t, w)
	if resp["id"] != hostID {
		t.Fatalf("expected id=%s, got %v", hostID, resp["id"])
	}
	if pw, ok := resp["ssh_password"]; ok && pw != "" {
		t.Fatal("ssh_password should be stripped")
	}
}

func TestAPI_GetHostActiveSession(t *testing.T) {
	router, _ := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	hostID := createTestHost(t, router, token)

	w := authGet(t, router, "/api/hosts/"+hostID+"/active-session", token)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	resp := decodeResponse(t, w)
	if resp["in_use"] != false {
		t.Fatalf("expected in_use=false, got %v", resp["in_use"])
	}
}

// ---------------------------------------------------------------------------
// Group Update + Mappings
// ---------------------------------------------------------------------------

func TestAPI_UpdateGroup(t *testing.T) {
	router, _ := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	// create
	w := authRequest(t, router, http.MethodPost, "/api/groups", token, map[string]any{
		"name":        "updatable",
		"description": "Will be updated",
		"permissions": []string{"connect_hosts"},
	})
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("create group: %d", w.Code)
	}
	created := decodeResponse(t, w)
	groupID, _ := created["id"].(string)

	// update
	w = authRequest(t, router, http.MethodPut, "/api/groups/"+groupID, token, map[string]any{
		"name":        "updated-name",
		"description": "Updated desc",
		"permissions": []string{"connect_hosts", "view_sessions"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("update group: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAPI_GroupMappings_CRUD(t *testing.T) {
	router, _ := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	// list (empty)
	w := authGet(t, router, "/api/group-mappings", token)
	if w.Code != http.StatusOK {
		t.Fatalf("list mappings: expected 200, got %d", w.Code)
	}

	// create
	w = authRequest(t, router, http.MethodPost, "/api/group-mappings", token, map[string]string{
		"external_group":   "okta-admins",
		"gatekeeper_group": "platform-admin",
	})
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("create mapping: expected 200/201, got %d: %s", w.Code, w.Body.String())
	}
	created := decodeResponse(t, w)
	mappingID, _ := created["id"].(string)
	if mappingID == "" {
		t.Fatal("expected mapping id")
	}

	// delete
	w = authRequest(t, router, http.MethodDelete, "/api/group-mappings/"+mappingID, token, nil)
	if w.Code != http.StatusNoContent && w.Code != http.StatusOK {
		t.Fatalf("delete mapping: expected 200/204, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Settings Update
// ---------------------------------------------------------------------------

func TestAPI_UpdateSettings(t *testing.T) {
	router, _ := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	w := authRequest(t, router, http.MethodPut, "/api/settings", token, map[string]any{
		"auth_mode":           "local",
		"session_ttl":         "12h",
		"mfa_policy":          "optional",
		"password_min_length": 12,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("update settings: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAPI_UpdateSettings_InvalidAuthMode(t *testing.T) {
	router, _ := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	w := authRequest(t, router, http.MethodPut, "/api/settings", token, map[string]any{
		"auth_mode": "invalid_mode",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid auth_mode, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// MFA Enroll
// ---------------------------------------------------------------------------

func TestAPI_MFA_Enroll(t *testing.T) {
	router, _ := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	w := authRequest(t, router, http.MethodPost, "/api/me/mfa/enroll", token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("mfa enroll: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	resp := decodeResponse(t, w)
	if resp["secret"] == nil || resp["secret"] == "" {
		t.Fatal("expected secret in enroll response")
	}
	if resp["qr_data_uri"] == nil || resp["qr_data_uri"] == "" {
		t.Fatal("expected qr_data_uri in enroll response")
	}
	if resp["recovery_codes"] == nil {
		t.Fatal("expected recovery_codes in enroll response")
	}
}

// ---------------------------------------------------------------------------
// Change Password
// ---------------------------------------------------------------------------

func TestAPI_ChangePassword(t *testing.T) {
	router, ctx := setupTestRouter(t)

	token := createUserAndLogin(t, router, ctx, "pwduser", "OldPassword123!", "user")

	w := authRequest(t, router, http.MethodPost, "/api/me/password", token, map[string]string{
		"current_password": "OldPassword123!",
		"new_password":     "NewPassword456!",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("change password: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAPI_ChangePassword_WrongCurrent(t *testing.T) {
	router, ctx := setupTestRouter(t)

	token := createUserAndLogin(t, router, ctx, "pwduser2", "Correct123!", "user")

	w := authRequest(t, router, http.MethodPost, "/api/me/password", token, map[string]string{
		"current_password": "WrongPassword!",
		"new_password":     "NewPass456!",
	})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong current password, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Access Requests
// ---------------------------------------------------------------------------

func TestAPI_AccessRequests(t *testing.T) {
	router, _ := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	hostID := createTestHost(t, router, token)

	// create request
	w := authRequest(t, router, http.MethodPost, "/api/access-requests", token, map[string]string{
		"host_id": hostID,
		"reason":  "need access for testing",
	})
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("create access request: expected 200/201, got %d: %s", w.Code, w.Body.String())
	}
	created := decodeResponse(t, w)
	reqID, _ := created["id"].(string)
	if reqID == "" {
		t.Fatal("expected request id")
	}

	// list pending
	w = authGet(t, router, "/api/access-requests", token)
	if w.Code != http.StatusOK {
		t.Fatalf("list requests: expected 200, got %d", w.Code)
	}

	// approve
	w = authRequest(t, router, http.MethodPost, "/api/access-requests/"+reqID+"/approve", token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("approve: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Access Windows
// ---------------------------------------------------------------------------

func TestAPI_AccessWindows_CRUD(t *testing.T) {
	router, _ := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	hostID := createTestHost(t, router, token)

	// create
	w := authRequest(t, router, http.MethodPost, "/api/access-windows", token, map[string]any{
		"entity_type": "host",
		"entity_id":   hostID,
		"days":        "1-5",
		"start_time":  "09:00",
		"end_time":    "17:00",
		"timezone":    "UTC",
	})
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("create window: expected 200/201, got %d: %s", w.Code, w.Body.String())
	}
	created := decodeResponse(t, w)
	winID, _ := created["id"].(string)
	if winID == "" {
		t.Fatal("expected window id")
	}

	// list
	w = authGet(t, router, "/api/access-windows", token)
	if w.Code != http.StatusOK {
		t.Fatalf("list windows: expected 200, got %d", w.Code)
	}

	// delete
	w = authRequest(t, router, http.MethodDelete, "/api/access-windows/"+winID, token, nil)
	if w.Code != http.StatusNoContent && w.Code != http.StatusOK {
		t.Fatalf("delete window: expected 200/204, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Audit Export
// ---------------------------------------------------------------------------

func TestAPI_AuditBulkExport(t *testing.T) {
	router, _ := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	w := authGet(t, router, "/api/audit/export?format=json", token)
	if w.Code != http.StatusOK {
		t.Fatalf("bulk export: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Encryption Status
// ---------------------------------------------------------------------------

func TestAPI_EncryptionStatus(t *testing.T) {
	router, _ := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	w := authGet(t, router, "/api/encryption/status", token)
	if w.Code != http.StatusOK {
		t.Fatalf("encryption status: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Admin Reset MFA
// ---------------------------------------------------------------------------

func TestAPI_AdminResetMFA(t *testing.T) {
	router, ctx := setupTestRouter(t)
	token := loginAsAdmin(t, router)

	u := &models.User{Username: "mfatarget", DisplayName: "MFA Target", Role: "user", AuthProvider: "local"}
	if err := ctx.Users.Create(u, "MfaTarget123!"); err != nil {
		t.Fatalf("create user: %v", err)
	}

	w := authRequest(t, router, http.MethodDelete, "/api/users/"+u.ID+"/mfa", token, nil)
	if w.Code != http.StatusNoContent && w.Code != http.StatusOK {
		t.Fatalf("admin reset mfa: expected 200/204, got %d: %s", w.Code, w.Body.String())
	}
}
