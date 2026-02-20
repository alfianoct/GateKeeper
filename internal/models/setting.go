package models

import (
	"strconv"
	"time"

	"github.com/judsenb/gatekeeper/internal/crypto"
	"github.com/judsenb/gatekeeper/internal/db"
)

// these get encrypted at rest when an encryption key is configured
var SensitiveSettings = map[string]bool{
	SettingOIDCClientSecret:   true,
	SettingLDAPBindPassword:   true,
	SettingAuditWebhookSecret: true,
	SettingSAMLSPKey:          true,
}

type SettingStore struct {
	DB            *db.DB
	EncryptionKey []byte // AES-256 key; nil = encryption disabled
}

// Get returns defaultVal on miss. sensitive values are decrypted transparently.
func (s *SettingStore) Get(key, defaultVal string) string {
	var val string
	err := s.DB.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&val)
	if err != nil {
		return defaultVal
	}
	if SensitiveSettings[key] && len(s.EncryptionKey) == crypto.KeySize {
		if decrypted, err := crypto.Decrypt(s.EncryptionKey, val); err == nil {
			return decrypted
		}
	}
	return val
}

func (s *SettingStore) Set(key, value string) error {
	stored := value
	if SensitiveSettings[key] && len(s.EncryptionKey) == crypto.KeySize && value != "" {
		if enc, err := crypto.Encrypt(s.EncryptionKey, []byte(value)); err == nil {
			stored = enc
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.DB.Exec(`INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at`, key, stored, now)
	return err
}

const (
	SettingInstanceName      = "instance_name"
	SettingAuthMode          = "auth_mode"         // "local", "oidc", "local+oidc", "ldap", "local+ldap"
	SettingSessionTTL        = "session_ttl"       // e.g. "24h"
	SettingSessionRecording  = "session_recording" // "true" / "false"
	SettingOIDCIssuer        = "oidc_issuer"
	SettingOIDCClientID      = "oidc_client_id"
	SettingOIDCClientSecret  = "oidc_client_secret"
	SettingOIDCRedirectURL   = "oidc_redirect_url"
	SettingOIDCAutoProvision = "oidc_auto_provision" // "true" / "false"
	SettingOIDCDefaultRole   = "oidc_default_role"   // "user" / "platform-admin"
	// LDAP
	SettingLDAPURL             = "ldap_url"               // e.g. "ldaps://dc.example.com:636"
	SettingLDAPBindDN          = "ldap_bind_dn"           // service account for search
	SettingLDAPBindPassword    = "ldap_bind_password"     // or from secrets
	SettingLDAPUserBase        = "ldap_user_base"         // e.g. "ou=users,dc=example,dc=com"
	SettingLDAPUserFilter      = "ldap_user_filter"       // e.g. "(sAMAccountName=%s)" or "(uid=%s)"
	SettingLDAPGroupAttr       = "ldap_group_attr"        // e.g. "memberOf"
	SettingLDAPUsernameAttr    = "ldap_username_attr"     // e.g. "sAMAccountName"
	SettingLDAPDisplayNameAttr = "ldap_display_name_attr" // e.g. "displayName"
	SettingLDAPAutoProvision   = "ldap_auto_provision"    // "true" / "false"
	SettingLDAPDefaultRole     = "ldap_default_role"      // "user" / "platform-admin"
	// SAML
	SettingSAMLIDPMetadataURL  = "saml_idp_metadata_url"  // e.g. "https://idp.example.com/metadata"
	SettingSAMLEntityID        = "saml_entity_id"         // SP entity ID, e.g. "https://gatekeeper.example.com"
	SettingSAMLACSURL          = "saml_acs_url"           // e.g. "https://gatekeeper.example.com/auth/saml/acs"
	SettingSAMLUsernameAttr    = "saml_username_attr"     // SAML attribute for username
	SettingSAMLDisplayNameAttr = "saml_display_name_attr" // SAML attribute for display name
	SettingSAMLGroupsAttr      = "saml_groups_attr"       // SAML attribute for group memberships
	SettingSAMLAutoProvision   = "saml_auto_provision"    // "true" / "false"
	SettingSAMLDefaultRole     = "saml_default_role"      // "user" / "platform-admin"
	SettingSAMLSPCert          = "saml_sp_cert"           // base64-encoded PEM (auto-generated)
	SettingSAMLSPKey           = "saml_sp_key"            // base64-encoded PEM (auto-generated)
	// MFA
	SettingMFAPolicy = "mfa_policy" // "optional" (default), "required_for_admins", "required_for_all"
	// Password policy
	SettingPasswordMinLength        = "password_min_length"        // default "12"
	SettingPasswordRequireUppercase = "password_require_uppercase" // "true" / "false"
	SettingPasswordRequireNumber    = "password_require_number"    // "true" / "false"
	SettingPasswordRequireSpecial   = "password_require_special"   // "true" / "false"
	SettingPasswordMaxAgeDays       = "password_max_age_days"      // "0" = disabled
	SettingPasswordHistoryCount     = "password_history_count"     // "0" = disabled
	// Session limits
	SettingMaxSessionsPerUser = "max_sessions_per_user" // 0 = unlimited (default)
	// Audit export
	SettingAuditWebhookURL     = "audit_webhook_url"     // e.g. "https://siem.example.com/webhook"
	SettingAuditWebhookSecret  = "audit_webhook_secret"  // HMAC-SHA256 signing key
	SettingAuditSyslogAddr     = "audit_syslog_addr"     // e.g. "udp://siem.example.com:514"
	SettingAuditSyslogFacility = "audit_syslog_facility" // integer, default "1" (user)
)

type PlatformSettings struct {
	InstanceName      string `json:"instance_name"`
	AuthMode          string `json:"auth_mode"`
	SessionTTL        string `json:"session_ttl"`
	SessionRecording  bool   `json:"session_recording"`
	OIDCIssuer        string `json:"oidc_issuer"`
	OIDCClientID      string `json:"oidc_client_id"`
	OIDCClientSecret  string `json:"oidc_client_secret"`
	OIDCRedirectURL   string `json:"oidc_redirect_url"`
	OIDCAutoProvision bool   `json:"oidc_auto_provision"`
	OIDCDefaultRole   string `json:"oidc_default_role"`
	// LDAP
	LDAPURL             string `json:"ldap_url"`
	LDAPBindDN          string `json:"ldap_bind_dn"`
	LDAPBindPassword    string `json:"ldap_bind_password"`
	LDAPUserBase        string `json:"ldap_user_base"`
	LDAPUserFilter      string `json:"ldap_user_filter"`
	LDAPGroupAttr       string `json:"ldap_group_attr"`
	LDAPUsernameAttr    string `json:"ldap_username_attr"`
	LDAPDisplayNameAttr string `json:"ldap_display_name_attr"`
	LDAPAutoProvision   bool   `json:"ldap_auto_provision"`
	LDAPDefaultRole     string `json:"ldap_default_role"`
	// SAML
	SAMLIDPMetadataURL  string `json:"saml_idp_metadata_url"`
	SAMLEntityID        string `json:"saml_entity_id"`
	SAMLACS             string `json:"saml_acs_url"`
	SAMLUsernameAttr    string `json:"saml_username_attr"`
	SAMLDisplayNameAttr string `json:"saml_display_name_attr"`
	SAMLGroupsAttr      string `json:"saml_groups_attr"`
	SAMLAutoProvision   bool   `json:"saml_auto_provision"`
	SAMLDefaultRole     string `json:"saml_default_role"`
	// MFA
	MFAPolicy string `json:"mfa_policy"`
	// Password policy
	PasswordMinLength        int  `json:"password_min_length"`
	PasswordRequireUppercase bool `json:"password_require_uppercase"`
	PasswordRequireNumber    bool `json:"password_require_number"`
	PasswordRequireSpecial   bool `json:"password_require_special"`
	PasswordMaxAgeDays       int  `json:"password_max_age_days"`
	PasswordHistoryCount     int  `json:"password_history_count"`
	// Session limits
	MaxSessionsPerUser int `json:"max_sessions_per_user"`
	// Audit export
	AuditWebhookURL     string `json:"audit_webhook_url"`
	AuditWebhookSecret  string `json:"audit_webhook_secret"`
	AuditSyslogAddr     string `json:"audit_syslog_addr"`
	AuditSyslogFacility int    `json:"audit_syslog_facility"`
}

func (s *SettingStore) LoadAll() *PlatformSettings {
	return &PlatformSettings{
		InstanceName:             s.Get(SettingInstanceName, "GateKeeper"),
		AuthMode:                 s.Get(SettingAuthMode, "local"),
		SessionTTL:               s.Get(SettingSessionTTL, "24h"),
		SessionRecording:         s.Get(SettingSessionRecording, "true") == "true",
		OIDCIssuer:               s.Get(SettingOIDCIssuer, ""),
		OIDCClientID:             s.Get(SettingOIDCClientID, ""),
		OIDCClientSecret:         s.Get(SettingOIDCClientSecret, ""),
		OIDCRedirectURL:          s.Get(SettingOIDCRedirectURL, ""),
		OIDCAutoProvision:        s.Get(SettingOIDCAutoProvision, "false") == "true",
		OIDCDefaultRole:          s.Get(SettingOIDCDefaultRole, "user"),
		LDAPURL:                  s.Get(SettingLDAPURL, ""),
		LDAPBindDN:               s.Get(SettingLDAPBindDN, ""),
		LDAPBindPassword:         s.Get(SettingLDAPBindPassword, ""),
		LDAPUserBase:             s.Get(SettingLDAPUserBase, ""),
		LDAPUserFilter:           s.Get(SettingLDAPUserFilter, "(uid=%s)"),
		LDAPGroupAttr:            s.Get(SettingLDAPGroupAttr, "memberOf"),
		LDAPUsernameAttr:         s.Get(SettingLDAPUsernameAttr, "uid"),
		LDAPDisplayNameAttr:      s.Get(SettingLDAPDisplayNameAttr, "displayName"),
		LDAPAutoProvision:        s.Get(SettingLDAPAutoProvision, "false") == "true",
		LDAPDefaultRole:          s.Get(SettingLDAPDefaultRole, "user"),
		SAMLIDPMetadataURL:       s.Get(SettingSAMLIDPMetadataURL, ""),
		SAMLEntityID:             s.Get(SettingSAMLEntityID, ""),
		SAMLACS:                  s.Get(SettingSAMLACSURL, ""),
		SAMLUsernameAttr:         s.Get(SettingSAMLUsernameAttr, ""),
		SAMLDisplayNameAttr:      s.Get(SettingSAMLDisplayNameAttr, ""),
		SAMLGroupsAttr:           s.Get(SettingSAMLGroupsAttr, ""),
		SAMLAutoProvision:        s.Get(SettingSAMLAutoProvision, "false") == "true",
		SAMLDefaultRole:          s.Get(SettingSAMLDefaultRole, "user"),
		MFAPolicy:                s.Get(SettingMFAPolicy, "optional"),
		PasswordMinLength:        atoi(s.Get(SettingPasswordMinLength, "12")),
		PasswordRequireUppercase: s.Get(SettingPasswordRequireUppercase, "true") == "true",
		PasswordRequireNumber:    s.Get(SettingPasswordRequireNumber, "true") == "true",
		PasswordRequireSpecial:   s.Get(SettingPasswordRequireSpecial, "true") == "true",
		PasswordMaxAgeDays:       atoi(s.Get(SettingPasswordMaxAgeDays, "0")),
		PasswordHistoryCount:     atoi(s.Get(SettingPasswordHistoryCount, "0")),
		MaxSessionsPerUser:       atoi(s.Get(SettingMaxSessionsPerUser, "0")),
		AuditWebhookURL:          s.Get(SettingAuditWebhookURL, ""),
		AuditWebhookSecret:       s.Get(SettingAuditWebhookSecret, ""),
		AuditSyslogAddr:          s.Get(SettingAuditSyslogAddr, ""),
		AuditSyslogFacility:      atoi(s.Get(SettingAuditSyslogFacility, "1")),
	}
}

func (s *SettingStore) SaveAll(ps *PlatformSettings) error {
	pairs := map[string]string{
		SettingInstanceName:             ps.InstanceName,
		SettingAuthMode:                 ps.AuthMode,
		SettingSessionTTL:               ps.SessionTTL,
		SettingSessionRecording:         boolStr(ps.SessionRecording),
		SettingOIDCIssuer:               ps.OIDCIssuer,
		SettingOIDCClientID:             ps.OIDCClientID,
		SettingOIDCClientSecret:         ps.OIDCClientSecret,
		SettingOIDCRedirectURL:          ps.OIDCRedirectURL,
		SettingOIDCAutoProvision:        boolStr(ps.OIDCAutoProvision),
		SettingOIDCDefaultRole:          ps.OIDCDefaultRole,
		SettingLDAPURL:                  ps.LDAPURL,
		SettingLDAPBindDN:               ps.LDAPBindDN,
		SettingLDAPBindPassword:         ps.LDAPBindPassword,
		SettingLDAPUserBase:             ps.LDAPUserBase,
		SettingLDAPUserFilter:           ps.LDAPUserFilter,
		SettingLDAPGroupAttr:            ps.LDAPGroupAttr,
		SettingLDAPUsernameAttr:         ps.LDAPUsernameAttr,
		SettingLDAPDisplayNameAttr:      ps.LDAPDisplayNameAttr,
		SettingLDAPAutoProvision:        boolStr(ps.LDAPAutoProvision),
		SettingLDAPDefaultRole:          ps.LDAPDefaultRole,
		SettingSAMLIDPMetadataURL:       ps.SAMLIDPMetadataURL,
		SettingSAMLEntityID:             ps.SAMLEntityID,
		SettingSAMLACSURL:               ps.SAMLACS,
		SettingSAMLUsernameAttr:         ps.SAMLUsernameAttr,
		SettingSAMLDisplayNameAttr:      ps.SAMLDisplayNameAttr,
		SettingSAMLGroupsAttr:           ps.SAMLGroupsAttr,
		SettingSAMLAutoProvision:        boolStr(ps.SAMLAutoProvision),
		SettingSAMLDefaultRole:          ps.SAMLDefaultRole,
		SettingMFAPolicy:                ps.MFAPolicy,
		SettingPasswordMinLength:        strconv.Itoa(ps.PasswordMinLength),
		SettingPasswordRequireUppercase: boolStr(ps.PasswordRequireUppercase),
		SettingPasswordRequireNumber:    boolStr(ps.PasswordRequireNumber),
		SettingPasswordRequireSpecial:   boolStr(ps.PasswordRequireSpecial),
		SettingPasswordMaxAgeDays:       strconv.Itoa(ps.PasswordMaxAgeDays),
		SettingPasswordHistoryCount:     strconv.Itoa(ps.PasswordHistoryCount),
		SettingMaxSessionsPerUser:       strconv.Itoa(ps.MaxSessionsPerUser),
		SettingAuditWebhookURL:          ps.AuditWebhookURL,
		SettingAuditWebhookSecret:       ps.AuditWebhookSecret,
		SettingAuditSyslogAddr:          ps.AuditSyslogAddr,
		SettingAuditSyslogFacility:      strconv.Itoa(ps.AuditSyslogFacility),
	}
	for k, v := range pairs {
		if err := s.Set(k, v); err != nil {
			return err
		}
	}
	return nil
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func atoi(s string) int {
	v, _ := strconv.Atoi(s)
	return v
}
