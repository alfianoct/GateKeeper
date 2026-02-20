package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/judsenb/gatekeeper/internal/auth"
	"github.com/judsenb/gatekeeper/internal/auth/mfa"
	"github.com/judsenb/gatekeeper/internal/models"
	"rsc.io/qr"
)

type MFAHandler struct {
	Users      *models.UserStore
	Sessions   *auth.SessionStore
	MFAPending *auth.MFAPendingStore
	Audit      *models.AuditStore
	Settings   *models.SettingStore
	UseTLS     bool
}

// Generates a TOTP secret and returns the otpauth URI + recovery codes.
func (h *MFAHandler) Enroll(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		jsonError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	if user.MFAEnabled {
		jsonError(w, http.StatusConflict, "MFA is already enabled — disable it first to re-enroll")
		return
	}

	if user.AuthProvider != "local" {
		jsonError(w, http.StatusBadRequest, "MFA enrollment is only available for local accounts")
		return
	}

	secret, err := mfa.GenerateSecret()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to generate TOTP secret")
		return
	}

	instanceName := "GateKeeper"
	if h.Settings != nil {
		if n := h.Settings.Get(models.SettingInstanceName, ""); n != "" {
			instanceName = n
		}
	}

	uri := mfa.GenerateURI(secret, user.Username, instanceName)

	recoveryCodes, err := mfa.GenerateRecoveryCodes()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to generate recovery codes")
		return
	}

	// secret saved but not enabled yet — needs confirmation with a valid code
	codesJSON, _ := json.Marshal(recoveryCodes)
	if err := h.Users.SetMFASecret(user.ID, secret); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to save TOTP secret")
		return
	}
	if err := h.Users.UpdateRecoveryCodes(user.ID, string(codesJSON)); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to save recovery codes")
		return
	}

	var qrDataURI string
	if code, err := qr.Encode(uri, qr.M); err == nil {
		qrDataURI = "data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG())
	}

	jsonResponse(w, http.StatusOK, map[string]any{
		"secret":         secret,
		"otpauth_uri":    uri,
		"recovery_codes": recoveryCodes,
		"qr_data_uri":    qrDataURI,
	})
}

// Validates the first TOTP code to activate MFA.
func (h *MFAHandler) Confirm(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		jsonError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	if user.MFAEnabled {
		jsonError(w, http.StatusConflict, "MFA is already enabled")
		return
	}

	fresh, err := h.Users.GetByID(user.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to load user")
		return
	}
	if fresh.MFASecret == "" {
		jsonError(w, http.StatusBadRequest, "no MFA enrollment in progress — call /api/me/mfa/enroll first")
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	valid, err := mfa.ValidateCode(fresh.MFASecret, strings.TrimSpace(req.Code))
	if err != nil || !valid {
		jsonError(w, http.StatusUnauthorized, "invalid TOTP code — check your authenticator app and try again")
		return
	}

	if err := h.Users.EnableMFA(user.ID, fresh.MFARecoveryCodes); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to enable MFA")
		return
	}

	h.Audit.Log(&models.AuditEntry{
		Action:   "mfa_enrolled",
		UserID:   user.ID,
		Username: user.Username,
		SourceIP: r.RemoteAddr,
	})

	jsonResponse(w, http.StatusOK, map[string]any{"mfa_enabled": true})
}

// Validates a TOTP code using a pending MFA token (unauthenticated endpoint).
func (h *MFAHandler) Verify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MFAToken string `json:"mfa_token"`
		Code     string `json:"code"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if req.MFAToken == "" || req.Code == "" {
		jsonError(w, http.StatusBadRequest, "mfa_token and code are required")
		return
	}

	userID, err := h.MFAPending.Validate(req.MFAToken)
	if err != nil {
		jsonError(w, http.StatusUnauthorized, "MFA token invalid or expired — please sign in again")
		return
	}

	user, err := h.Users.GetByID(userID)
	if err != nil {
		jsonError(w, http.StatusUnauthorized, "user not found")
		return
	}

	valid, err := mfa.ValidateCode(user.MFASecret, strings.TrimSpace(req.Code))
	if err != nil || !valid {
		h.Audit.Log(&models.AuditEntry{
			Action:   "mfa_failed",
			UserID:   user.ID,
			Username: user.Username,
			Detail:   "invalid TOTP code",
			SourceIP: r.RemoteAddr,
		})
		jsonError(w, http.StatusUnauthorized, "invalid MFA code")
		return
	}

	// MFA passed — now they get a real session
	token, err := h.Sessions.Create(user.ID, r.RemoteAddr, r.UserAgent())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	h.Users.TouchLogin(user.ID)
	h.Audit.Log(&models.AuditEntry{
		Action:   "mfa_verified",
		UserID:   user.ID,
		Username: user.Username,
		Detail:   "totp",
		SourceIP: r.RemoteAddr,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(h.Sessions.Duration.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   h.UseTLS,
	})

	jsonResponse(w, http.StatusOK, map[string]any{
		"user": map[string]any{
			"id":           user.ID,
			"username":     user.Username,
			"display_name": user.DisplayName,
			"role":         user.Role,
		},
	})
}

// Accepts a single-use recovery code instead of TOTP.
func (h *MFAHandler) Recover(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MFAToken     string `json:"mfa_token"`
		RecoveryCode string `json:"recovery_code"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if req.MFAToken == "" || req.RecoveryCode == "" {
		jsonError(w, http.StatusBadRequest, "mfa_token and recovery_code are required")
		return
	}

	userID, err := h.MFAPending.Validate(req.MFAToken)
	if err != nil {
		jsonError(w, http.StatusUnauthorized, "MFA token invalid or expired — please sign in again")
		return
	}

	user, err := h.Users.GetByID(userID)
	if err != nil {
		jsonError(w, http.StatusUnauthorized, "user not found")
		return
	}

	var codes []string
	if user.MFARecoveryCodes != "" {
		json.Unmarshal([]byte(user.MFARecoveryCodes), &codes)
	}

	inputCode := strings.ToLower(strings.TrimSpace(req.RecoveryCode))
	found := -1
	for i, c := range codes {
		if strings.ToLower(c) == inputCode {
			found = i
			break
		}
	}

	if found < 0 {
		h.Audit.Log(&models.AuditEntry{
			Action:   "mfa_failed",
			UserID:   user.ID,
			Username: user.Username,
			Detail:   "invalid recovery code",
			SourceIP: r.RemoteAddr,
		})
		jsonError(w, http.StatusUnauthorized, "invalid recovery code")
		return
	}

	// burn the used code
	codes = append(codes[:found], codes[found+1:]...)
	updatedJSON, _ := json.Marshal(codes)
	h.Users.UpdateRecoveryCodes(user.ID, string(updatedJSON))

	token, err := h.Sessions.Create(user.ID, r.RemoteAddr, r.UserAgent())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	h.Users.TouchLogin(user.ID)
	h.Audit.Log(&models.AuditEntry{
		Action:   "mfa_verified",
		UserID:   user.ID,
		Username: user.Username,
		Detail:   "recovery code",
		SourceIP: r.RemoteAddr,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(h.Sessions.Duration.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   h.UseTLS,
	})

	jsonResponse(w, http.StatusOK, map[string]any{
		"user": map[string]any{
			"id":           user.ID,
			"username":     user.Username,
			"display_name": user.DisplayName,
			"role":         user.Role,
		},
		"recovery_codes_remaining": len(codes),
	})
}

// Lets a user turn off their own MFA (requires valid TOTP code).
func (h *MFAHandler) Disable(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		jsonError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	fresh, _ := h.Users.GetByID(user.ID)
	if fresh == nil || !fresh.MFAEnabled {
		jsonError(w, http.StatusBadRequest, "MFA is not enabled")
		return
	}

	valid, _ := mfa.ValidateCode(fresh.MFASecret, strings.TrimSpace(req.Code))
	if !valid {
		jsonError(w, http.StatusUnauthorized, "invalid TOTP code")
		return
	}

	if err := h.Users.DisableMFA(user.ID); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to disable MFA")
		return
	}

	h.Audit.Log(&models.AuditEntry{
		Action:   "mfa_reset",
		UserID:   user.ID,
		Username: user.Username,
		Detail:   "self-disable",
		SourceIP: r.RemoteAddr,
	})

	jsonResponse(w, http.StatusOK, map[string]any{"mfa_enabled": false})
}

// Admin force-resets a user's MFA.
func (h *MFAHandler) AdminReset(w http.ResponseWriter, r *http.Request) {
	caller := UserFromContext(r.Context())
	if caller == nil {
		jsonError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	targetID := chi.URLParam(r, "id")

	target, err := h.Users.GetByID(targetID)
	if err != nil {
		jsonError(w, http.StatusNotFound, "user not found")
		return
	}

	if err := h.Users.DisableMFA(targetID); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to reset MFA")
		return
	}

	h.Audit.Log(&models.AuditEntry{
		Action:   "mfa_reset",
		UserID:   caller.ID,
		Username: caller.Username,
		TargetID: target.ID,
		Target:   target.Username,
		Detail:   "admin reset",
		SourceIP: r.RemoteAddr,
	})

	w.WriteHeader(http.StatusNoContent)
}

// Lets a user change their own password (local accounts only).
func (h *MFAHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		jsonError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	if user.AuthProvider != "local" {
		jsonError(w, http.StatusBadRequest, "password change is only available for local accounts")
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if req.CurrentPassword == "" || req.NewPassword == "" {
		jsonError(w, http.StatusBadRequest, "current_password and new_password required")
		return
	}

	if !h.Users.CheckPassword(user, req.CurrentPassword) {
		jsonError(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}

	policy := loadPasswordPolicy(h.Settings)
	if err := auth.ValidatePasswordPolicy(req.NewPassword, policy); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	historyCount := 0
	if h.Settings != nil {
		historyCount = atoi(h.Settings.Get(models.SettingPasswordHistoryCount, "0"))
	}
	if historyCount > 0 {
		reused, err := h.Users.CheckPasswordHistory(user.ID, req.NewPassword, historyCount)
		if err == nil && reused {
			jsonError(w, http.StatusBadRequest, "password was recently used — choose a different one")
			return
		}
	}

	if historyCount > 0 && user.PasswordHash != "" {
		h.Users.AddPasswordHistory(user.ID, user.PasswordHash)
	}

	if err := h.Users.SetPassword(user.ID, req.NewPassword); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to update password")
		return
	}

	h.Audit.Log(&models.AuditEntry{
		Action:   "password_changed",
		UserID:   user.ID,
		Username: user.Username,
		SourceIP: r.RemoteAddr,
	})

	jsonResponse(w, http.StatusOK, map[string]any{"password_changed": true})
}

func (h *MFAHandler) GetMFAStatus(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		jsonError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	fresh, _ := h.Users.GetByID(user.ID)
	if fresh == nil {
		jsonError(w, http.StatusInternalServerError, "failed to load user")
		return
	}

	remaining := 0
	if fresh.MFARecoveryCodes != "" {
		var codes []string
		json.Unmarshal([]byte(fresh.MFARecoveryCodes), &codes)
		remaining = len(codes)
	}

	policy := "optional"
	if h.Settings != nil {
		policy = h.Settings.Get(models.SettingMFAPolicy, "optional")
	}

	required := policy == "required_for_all" || (policy == "required_for_admins" && fresh.Role == "platform-admin")

	jsonResponse(w, http.StatusOK, map[string]any{
		"mfa_enabled":              fresh.MFAEnabled,
		"mfa_required":             required,
		"mfa_policy":               policy,
		"recovery_codes_remaining": remaining,
		"is_local":                 fresh.AuthProvider == "local",
	})
}

func loadPasswordPolicy(settings *models.SettingStore) auth.PasswordPolicy {
	if settings == nil {
		return auth.DefaultPasswordPolicy()
	}
	return auth.PasswordPolicy{
		MinLength:        atoi(settings.Get(models.SettingPasswordMinLength, "12")),
		RequireUppercase: settings.Get(models.SettingPasswordRequireUppercase, "true") == "true",
		RequireNumber:    settings.Get(models.SettingPasswordRequireNumber, "true") == "true",
		RequireSpecial:   settings.Get(models.SettingPasswordRequireSpecial, "true") == "true",
	}
}

func atoi(s string) int {
	v := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			v = v*10 + int(c-'0')
		}
	}
	return v
}
