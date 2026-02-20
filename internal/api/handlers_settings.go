package api

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/judsenb/gatekeeper/internal/audit"
	"github.com/judsenb/gatekeeper/internal/models"
)

type SettingsHandler struct {
	Settings   *models.SettingStore
	Audit      *models.AuditStore
	Dispatcher *audit.Dispatcher
}

// Returns all settings with secrets masked.
func (h *SettingsHandler) GetSettings(w http.ResponseWriter, r *http.Request) {
	ps := h.Settings.LoadAll()
	// never send actual secrets to the browser
	if ps.OIDCClientSecret != "" {
		ps.OIDCClientSecret = "••••••••"
	}
	if ps.LDAPBindPassword != "" {
		ps.LDAPBindPassword = "••••••••"
	}
	if ps.AuditWebhookSecret != "" {
		ps.AuditWebhookSecret = "••••••••"
	}
	jsonResponse(w, http.StatusOK, ps)
}

func (h *SettingsHandler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	var req models.PlatformSettings
	if err := decodeJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	req.AuthMode = strings.ToLower(strings.TrimSpace(req.AuthMode))
	validModes := map[string]bool{
		"local": true, "oidc": true, "local+oidc": true,
		"ldap": true, "local+ldap": true,
		"saml": true, "local+saml": true,
	}
	if !validModes[req.AuthMode] {
		jsonError(w, http.StatusBadRequest, "auth_mode must be one of: local, oidc, local+oidc, ldap, local+ldap, saml, local+saml")
		return
	}

	req.SessionTTL = strings.TrimSpace(req.SessionTTL)
	if req.SessionTTL == "" {
		req.SessionTTL = "24h"
	}

	req.OIDCDefaultRole = strings.TrimSpace(req.OIDCDefaultRole)
	if req.OIDCDefaultRole == "" {
		req.OIDCDefaultRole = "user"
	}
	if req.OIDCDefaultRole != "user" && req.OIDCDefaultRole != "platform-admin" {
		jsonError(w, http.StatusBadRequest, "oidc_default_role must be 'user' or 'platform-admin'")
		return
	}
	// yeah this is a scary default to set, but it's what they asked for
	if req.OIDCDefaultRole == "platform-admin" {
		slog.Warn("OIDC default role set to platform-admin, all new OIDC users will be admins")
	}

	// if the masked placeholder came back, keep the existing secret
	if req.OIDCClientSecret == "••••••••" || req.OIDCClientSecret == "" {
		existing := h.Settings.Get(models.SettingOIDCClientSecret, "")
		req.OIDCClientSecret = existing
	}
	if req.LDAPBindPassword == "••••••••" || req.LDAPBindPassword == "" {
		existing := h.Settings.Get(models.SettingLDAPBindPassword, "")
		req.LDAPBindPassword = existing
	}
	if req.AuditWebhookSecret == "••••••••" || req.AuditWebhookSecret == "" {
		existing := h.Settings.Get(models.SettingAuditWebhookSecret, "")
		req.AuditWebhookSecret = existing
	}

	req.LDAPDefaultRole = strings.TrimSpace(req.LDAPDefaultRole)
	if req.LDAPDefaultRole == "" {
		req.LDAPDefaultRole = "user"
	}
	if req.LDAPDefaultRole != "user" && req.LDAPDefaultRole != "platform-admin" {
		jsonError(w, http.StatusBadRequest, "ldap_default_role must be 'user' or 'platform-admin'")
		return
	}

	if req.AuthMode == "oidc" || req.AuthMode == "local+oidc" {
		if strings.TrimSpace(req.OIDCIssuer) == "" {
			jsonError(w, http.StatusBadRequest, "oidc_issuer is required when auth mode includes OIDC")
			return
		}
		if strings.TrimSpace(req.OIDCClientID) == "" {
			jsonError(w, http.StatusBadRequest, "oidc_client_id is required when auth mode includes OIDC")
			return
		}
	}

	req.SAMLDefaultRole = strings.TrimSpace(req.SAMLDefaultRole)
	if req.SAMLDefaultRole == "" {
		req.SAMLDefaultRole = "user"
	}
	if req.SAMLDefaultRole != "user" && req.SAMLDefaultRole != "platform-admin" {
		jsonError(w, http.StatusBadRequest, "saml_default_role must be 'user' or 'platform-admin'")
		return
	}

	if req.AuthMode == "saml" || req.AuthMode == "local+saml" {
		if strings.TrimSpace(req.SAMLIDPMetadataURL) == "" {
			jsonError(w, http.StatusBadRequest, "saml_idp_metadata_url is required when auth mode includes SAML")
			return
		}
		if strings.TrimSpace(req.SAMLEntityID) == "" {
			jsonError(w, http.StatusBadRequest, "saml_entity_id is required when auth mode includes SAML")
			return
		}
		if strings.TrimSpace(req.SAMLACS) == "" {
			jsonError(w, http.StatusBadRequest, "saml_acs_url is required when auth mode includes SAML")
			return
		}
	}

	if req.AuthMode == "ldap" || req.AuthMode == "local+ldap" {
		if strings.TrimSpace(req.LDAPURL) == "" {
			jsonError(w, http.StatusBadRequest, "ldap_url is required when auth mode includes LDAP")
			return
		}
		if strings.TrimSpace(req.LDAPUserBase) == "" {
			jsonError(w, http.StatusBadRequest, "ldap_user_base is required when auth mode includes LDAP")
			return
		}
	}

	req.MFAPolicy = strings.TrimSpace(req.MFAPolicy)
	if req.MFAPolicy == "" {
		req.MFAPolicy = "optional"
	}
	validPolicies := map[string]bool{"optional": true, "required_for_admins": true, "required_for_all": true}
	if !validPolicies[req.MFAPolicy] {
		jsonError(w, http.StatusBadRequest, "mfa_policy must be 'optional', 'required_for_admins', or 'required_for_all'")
		return
	}

	if req.PasswordMinLength < 8 {
		req.PasswordMinLength = 8
	}
	if req.PasswordMinLength > 128 {
		req.PasswordMinLength = 128
	}
	if req.PasswordMaxAgeDays < 0 {
		req.PasswordMaxAgeDays = 0
	}
	if req.PasswordHistoryCount < 0 {
		req.PasswordHistoryCount = 0
	}

	if err := h.Settings.SaveAll(&req); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to save settings")
		return
	}

	user := UserFromContext(r.Context())
	if user != nil {
		h.Audit.Log(&models.AuditEntry{
			Action:   "settings_updated",
			UserID:   user.ID,
			Username: user.Username,
			Detail:   "auth_mode=" + req.AuthMode,
			SourceIP: r.RemoteAddr,
		})
	}

	saved := h.Settings.LoadAll()
	if saved.OIDCClientSecret != "" {
		saved.OIDCClientSecret = "••••••••"
	}
	if saved.LDAPBindPassword != "" {
		saved.LDAPBindPassword = "••••••••"
	}
	if saved.AuditWebhookSecret != "" {
		saved.AuditWebhookSecret = "••••••••"
	}

	// hot-reload exporters so you don't have to restart
	if h.Dispatcher != nil {
		ConfigureAuditExporters(h.Dispatcher, h.Settings)
	}

	jsonResponse(w, http.StatusOK, saved)
}
