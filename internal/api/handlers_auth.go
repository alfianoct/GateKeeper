package api

import (
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/judsenb/gatekeeper/internal/auth"
	ldappkg "github.com/judsenb/gatekeeper/internal/auth/ldap"
	samlpkg "github.com/judsenb/gatekeeper/internal/auth/saml"
	"github.com/judsenb/gatekeeper/internal/instance"
	"github.com/judsenb/gatekeeper/internal/metrics"
	"github.com/judsenb/gatekeeper/internal/models"
	"github.com/judsenb/gatekeeper/internal/secrets"
)

type AuthHandler struct {
	Users          *models.UserStore
	Groups         *models.GroupStore
	Sessions       *auth.SessionStore
	SSHSessions    *models.SessionStore
	MFAPending     *auth.MFAPendingStore
	Audit          *models.AuditStore
	Settings       *models.SettingStore
	GroupMappings  *models.GroupMappingStore
	OIDC           *auth.OIDCProvider
	SAML           *samlpkg.Provider
	Secrets        secrets.Backend
	UseTLS         bool
	DeploymentMode string
}

// When auth mode includes LDAP, tries LDAP first then falls back to local.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	mode := "local"
	if h.Settings != nil {
		mode = h.Settings.Get(models.SettingAuthMode, "local")
	}
	if mode == "oidc" || mode == "saml" {
		jsonError(w, http.StatusBadRequest, "password login is disabled — use SSO")
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		jsonError(w, http.StatusBadRequest, "username and password required")
		return
	}

	var user *models.User
	var err error
	tryLDAP := (mode == "ldap" || mode == "local+ldap") && h.Settings != nil && h.Settings.Get(models.SettingLDAPURL, "") != ""

	if tryLDAP {
		bindPassword := h.Settings.Get(models.SettingLDAPBindPassword, "")
		if h.Secrets != nil {
			if s, _ := h.Secrets.GetSecret(secrets.KeyLDAPBindPassword); s != "" {
				bindPassword = s
			}
		}
		cfg := ldappkg.LoadConfig(h.Settings, bindPassword)
		info, lerr := ldappkg.Authenticate(cfg, req.Username, req.Password)
		if lerr == nil {
			user, err = h.findOrCreateLDAPUser(info)
			if err != nil {
				metrics.LoginsFailed.Add(1)
				h.Audit.Log(&models.AuditEntry{
					Action:   "login_failed",
					Username: req.Username,
					Detail:   err.Error(),
					SourceIP: r.RemoteAddr,
				})
				jsonError(w, http.StatusInternalServerError, "user provisioning failed")
				return
			}
		} else if mode == "ldap" {
			metrics.LoginsFailed.Add(1)
			h.Audit.Log(&models.AuditEntry{
				Action:   "login_failed",
				Username: req.Username,
				Detail:   lerr.Error(),
				SourceIP: r.RemoteAddr,
			})
			jsonError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
	}

	if user == nil && (mode == "local" || mode == "local+ldap" || mode == "local+oidc" || mode == "local+saml") {
		user, err = auth.Authenticate(h.Users, req.Username, req.Password)
	}

	if user == nil || err != nil {
		metrics.LoginsFailed.Add(1)
		h.Audit.Log(&models.AuditEntry{
			Action:   "login_failed",
			Username: req.Username,
			Detail:   fmt.Sprintf("%v", err),
			SourceIP: r.RemoteAddr,
		})
		jsonError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	mfaPolicy := "optional"
	if h.Settings != nil {
		mfaPolicy = h.Settings.Get(models.SettingMFAPolicy, "optional")
	}
	mfaRequired := user.MFAEnabled
	if !mfaRequired && mfaPolicy == "required_for_all" && user.AuthProvider == "local" {
		mfaRequired = true
	}
	if !mfaRequired && mfaPolicy == "required_for_admins" && user.Role == "platform-admin" && user.AuthProvider == "local" {
		mfaRequired = true
	}

	// MFA enabled — issue a pending token, not a real session yet
	if user.MFAEnabled && h.MFAPending != nil {
		mfaToken, err := h.MFAPending.Create(user.ID, r.RemoteAddr, r.UserAgent())
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "failed to create MFA challenge")
			return
		}
		h.Audit.Log(&models.AuditEntry{
			Action:   "login",
			UserID:   user.ID,
			Username: user.Username,
			Detail:   "password ok, mfa pending",
			SourceIP: r.RemoteAddr,
		})
		jsonResponse(w, http.StatusOK, map[string]any{
			"mfa_required": true,
			"mfa_token":    mfaToken,
		})
		return
	}

	// policy says MFA required but user hasn't enrolled yet — force enrollment
	if mfaRequired && !user.MFAEnabled && user.AuthProvider == "local" {
		mfaToken, err := h.MFAPending.Create(user.ID, r.RemoteAddr, r.UserAgent())
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "failed to create MFA challenge")
			return
		}
		jsonResponse(w, http.StatusOK, map[string]any{
			"mfa_enrollment_required": true,
			"mfa_token":               mfaToken,
		})
		return
	}

	// password expired — give them a session but frontend forces password change
	if user.AuthProvider == "local" && h.Settings != nil {
		maxAgeDays := h.Settings.Get(models.SettingPasswordMaxAgeDays, "0")
		if maxAge := atoiSafe(maxAgeDays); maxAge > 0 && user.PasswordChangedAt != "" {
			if isPasswordExpired(user.PasswordChangedAt, maxAge) {
				metrics.LoginsSuccess.Add(1)
				token, err := h.Sessions.Create(user.ID, r.RemoteAddr, r.UserAgent())
				if err != nil {
					jsonError(w, http.StatusInternalServerError, "failed to create session")
					return
				}
				h.Users.TouchLogin(user.ID)
				h.Audit.Log(&models.AuditEntry{
					Action:   "password_expired",
					UserID:   user.ID,
					Username: user.Username,
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
					"password_expired": true,
					"user": map[string]any{
						"id":       user.ID,
						"username": user.Username,
					},
				})
				return
			}
		}
	}

	metrics.LoginsSuccess.Add(1)
	token, err := h.Sessions.Create(user.ID, r.RemoteAddr, r.UserAgent())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	h.Users.TouchLogin(user.ID)

	detail := "local auth"
	if user.AuthProvider == "ldap" {
		detail = "ldap"
	} else if user.AuthProvider == "oidc" {
		detail = "oidc"
	}
	h.Audit.Log(&models.AuditEntry{
		Action:   "login",
		UserID:   user.ID,
		Username: user.Username,
		Detail:   detail,
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
			"groups":       strings.Split(user.Groups, ","),
		},
	})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil && cookie.Value != "" {
		h.Sessions.Destroy(cookie.Value)
	}

	// cookie attrs must match login or browsers won't clear it
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   h.UseTLS,
	})

	user := UserFromContext(r.Context())
	if user != nil {
		h.Audit.Log(&models.AuditEntry{
			Action:   "logout",
			UserID:   user.ID,
			Username: user.Username,
			SourceIP: r.RemoteAddr,
		})
	}

	w.WriteHeader(http.StatusNoContent)
}

// Returns the authenticated user with effective permissions.
func (h *AuthHandler) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		jsonError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	groups := []string{}
	if user.Groups != "" {
		groups = strings.Split(user.Groups, ",")
	}

	var permissions []string
	if user.Role == "platform-admin" {
		permissions = models.ValidPermissions
	} else {
		perms, err := h.Groups.EffectivePermissions(groups)
		if err != nil {
			perms = []string{}
		}
		permissions = perms
	}

	instanceName := h.Settings.Get(models.SettingInstanceName, "GateKeeper")

	activeSessionCount := 0
	if h.SSHSessions != nil {
		activeSessionCount, _ = h.SSHSessions.CountActiveByUserID(user.ID)
	}

	jsonResponse(w, http.StatusOK, map[string]any{
		"id":                   user.ID,
		"username":             user.Username,
		"display_name":         user.DisplayName,
		"role":                 user.Role,
		"groups":               groups,
		"permissions":          permissions,
		"mfa_enabled":          user.MFAEnabled,
		"auth_provider":        user.AuthProvider,
		"instance_id":          instance.ID(),
		"instance_name":        instanceName,
		"deployment_mode":      h.DeploymentMode,
		"active_session_count": activeSessionCount,
	})
}

// Called before login — must be unauthenticated.
func (h *AuthHandler) GetAuthProviders(w http.ResponseWriter, r *http.Request) {
	mode := "local"
	if h.Settings != nil {
		mode = h.Settings.Get(models.SettingAuthMode, "local")
	}

	showLocal := mode == "local" || mode == "local+oidc" || mode == "local+ldap" || mode == "local+saml"
	showOIDC := mode == "oidc" || mode == "local+oidc"
	oidcReady := showOIDC && h.OIDC != nil && h.OIDC.IsConfigured()
	showLDAP := mode == "ldap" || mode == "local+ldap"
	ldapReady := showLDAP && h.Settings != nil && h.Settings.Get(models.SettingLDAPURL, "") != "" && h.Settings.Get(models.SettingLDAPUserBase, "") != ""
	showSAML := mode == "saml" || mode == "local+saml"
	samlReady := showSAML && h.SAML != nil && h.SAML.IsConfigured()

	instanceName := ""
	if h.Settings != nil {
		instanceName = h.Settings.Get(models.SettingInstanceName, "")
	}

	jsonResponse(w, http.StatusOK, map[string]any{
		"auth_mode":     mode,
		"local":         showLocal,
		"oidc":          showOIDC,
		"oidc_ready":    oidcReady,
		"ldap":          showLDAP,
		"ldap_ready":    ldapReady,
		"saml":          showSAML,
		"saml_ready":    samlReady,
		"instance_name": instanceName,
	})
}

// Redirects to OIDC authorization endpoint.
func (h *AuthHandler) OIDCRedirect(w http.ResponseWriter, r *http.Request) {
	mode := "local"
	if h.Settings != nil {
		mode = h.Settings.Get(models.SettingAuthMode, "local")
	}
	if mode != "oidc" && mode != "local+oidc" {
		jsonError(w, http.StatusBadRequest, "OIDC login is not enabled")
		return
	}

	if h.OIDC == nil {
		jsonError(w, http.StatusServiceUnavailable, "OIDC provider not initialised")
		return
	}

	if err := h.OIDC.Refresh(h.Settings, h.Secrets); err != nil {
		slog.Warn("OIDC refresh error", "err", err)
		jsonError(w, http.StatusServiceUnavailable, "OIDC provider configuration error")
		return
	}

	state, err := auth.GenerateState()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to generate state")
		return
	}

	// short-lived CSRF cookie for the OIDC round-trip
	http.SetCookie(w, &http.Cookie{
		Name:     "gk_oidc_state",
		Value:    state,
		Path:     "/",
		MaxAge:   300,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode, // Lax required for OIDC redirect
	})

	url, err := h.OIDC.AuthCodeURL(state)
	if err != nil {
		jsonError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	http.Redirect(w, r, url, http.StatusFound)
}

// Exchanges OIDC code for tokens and creates a session.
func (h *AuthHandler) OIDCCallback(w http.ResponseWriter, r *http.Request) {
	stateCookie, err := r.Cookie("gk_oidc_state")
	if err != nil || stateCookie.Value == "" {
		http.Error(w, "Missing OIDC state cookie — please try logging in again", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("state") != stateCookie.Value {
		http.Error(w, "OIDC state mismatch — possible CSRF attack", http.StatusBadRequest)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "gk_oidc_state",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	// whitelist error params to avoid open redirect via error_description
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		desc := r.URL.Query().Get("error_description")
		slog.Warn("OIDC error", "error", errParam, "description", desc)
		metrics.LoginsFailed.Add(1)
		allowedErrors := map[string]bool{
			"exchange_failed":      true,
			"provisioning_failed":  true,
			"session_failed":       true,
			"access_denied":        true,
			"login_required":       true,
			"interaction_required": true,
		}
		redirectError := "exchange_failed"
		if allowedErrors[errParam] {
			redirectError = errParam
		}
		http.Redirect(w, r, "/?oidc_error="+redirectError, http.StatusFound)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	claims, err := h.OIDC.Exchange(r.Context(), code)
	if err != nil {
		slog.Error("OIDC exchange failed", "err", err)
		metrics.LoginsFailed.Add(1)
		http.Redirect(w, r, "/?oidc_error=exchange_failed", http.StatusFound)
		return
	}

	user, err := h.findOrCreateOIDCUser(claims)
	if err != nil {
		slog.Error("OIDC user provisioning failed", "err", err)
		metrics.LoginsFailed.Add(1)
		h.Audit.Log(&models.AuditEntry{
			Action:   "oidc_login_failed",
			Username: claims.PreferredUsername,
			Detail:   err.Error(),
			SourceIP: r.RemoteAddr,
		})
		http.Redirect(w, r, "/?oidc_error=provisioning_failed", http.StatusFound)
		return
	}

	token, err := h.Sessions.Create(user.ID, r.RemoteAddr, r.UserAgent())
	if err != nil {
		slog.Error("OIDC session creation failed", "err", err)
		metrics.LoginsFailed.Add(1)
		http.Redirect(w, r, "/?oidc_error=session_failed", http.StatusFound)
		return
	}
	metrics.LoginsSuccess.Add(1)

	h.Users.TouchLogin(user.ID)

	h.Audit.Log(&models.AuditEntry{
		Action:   "login",
		UserID:   user.ID,
		Username: user.Username,
		Detail:   "oidc (" + claims.Subject + ")",
		SourceIP: r.RemoteAddr,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(h.Sessions.Duration.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode, // Lax so the redirect from the IdP works
		Secure:   h.UseTLS,
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *AuthHandler) findOrCreateOIDCUser(claims *auth.OIDCClaims) (*models.User, error) {
	resolvedGroups := claims.Groups
	if h.GroupMappings != nil {
		mapped, err := h.GroupMappings.ResolveGroups(claims.Groups)
		if err != nil {
			slog.Warn("group mapping resolution failed", "err", err)
		} else {
			resolvedGroups = mapped
		}
	}

	user, err := h.Users.GetByOIDCSubject(claims.Subject)
	if err == nil {
		if user.Disabled {
			return nil, fmt.Errorf("account disabled")
		}
		// re-sync groups from IdP on every login
		user.Groups = strings.Join(resolvedGroups, ",")
		if claims.Name != "" {
			user.DisplayName = claims.Name
		}
		h.Users.Update(user)
		return user, nil
	}

	if err != sql.ErrNoRows {
		return nil, fmt.Errorf("lookup OIDC user: %w", err)
	}

	autoProvision := false
	defaultRole := "user"
	if h.Settings != nil {
		autoProvision = h.Settings.Get(models.SettingOIDCAutoProvision, "false") == "true"
		defaultRole = h.Settings.Get(models.SettingOIDCDefaultRole, "user")
	}

	if !autoProvision {
		return nil, fmt.Errorf("user %s not provisioned and auto-provisioning is disabled", claims.PreferredUsername)
	}

	newUser := &models.User{
		Username:     claims.PreferredUsername,
		DisplayName:  claims.Name,
		Role:         defaultRole,
		Groups:       strings.Join(resolvedGroups, ","),
		AuthProvider: "oidc",
		OIDCSubject:  claims.Subject,
	}

	if err := h.Users.CreateOIDC(newUser); err != nil {
		return nil, fmt.Errorf("auto-provision user: %w", err)
	}

	slog.Info("auto-provisioned OIDC user", "username", newUser.Username, "sub", claims.Subject, "role", defaultRole)
	return newUser, nil
}

func (h *AuthHandler) findOrCreateLDAPUser(info *ldappkg.UserInfo) (*models.User, error) {
	resolvedGroups := info.Groups
	if h.GroupMappings != nil {
		mapped, err := h.GroupMappings.ResolveGroups(info.Groups)
		if err != nil {
			slog.Warn("LDAP group mapping resolution failed", "err", err)
		} else {
			resolvedGroups = mapped
		}
	}

	user, err := h.Users.GetByAuthProviderAndSubject("ldap", info.DN)
	if err == nil {
		if user.Disabled {
			return nil, fmt.Errorf("account disabled")
		}
		user.Groups = strings.Join(resolvedGroups, ",")
		if info.DisplayName != "" {
			user.DisplayName = info.DisplayName
		}
		h.Users.Update(user)
		return user, nil
	}
	if err != sql.ErrNoRows {
		return nil, fmt.Errorf("lookup LDAP user: %w", err)
	}

	autoProvision := false
	defaultRole := "user"
	if h.Settings != nil {
		autoProvision = h.Settings.Get(models.SettingLDAPAutoProvision, "false") == "true"
		defaultRole = h.Settings.Get(models.SettingLDAPDefaultRole, "user")
	}
	if !autoProvision {
		return nil, fmt.Errorf("user %s not provisioned and LDAP auto-provisioning is disabled", info.Username)
	}

	newUser := &models.User{
		Username:     info.Username,
		DisplayName:  info.DisplayName,
		Role:         defaultRole,
		Groups:       strings.Join(resolvedGroups, ","),
		AuthProvider: "ldap",
		OIDCSubject:  info.DN,
	}
	if err := h.Users.CreateExternal(newUser, "ldap"); err != nil {
		return nil, fmt.Errorf("auto-provision LDAP user: %w", err)
	}
	slog.Info("auto-provisioned LDAP user", "username", newUser.Username, "dn", info.DN, "role", defaultRole)
	return newUser, nil
}

// Redirects to SAML IdP.
func (h *AuthHandler) SAMLRedirect(w http.ResponseWriter, r *http.Request) {
	mode := "local"
	if h.Settings != nil {
		mode = h.Settings.Get(models.SettingAuthMode, "local")
	}
	if mode != "saml" && mode != "local+saml" {
		jsonError(w, http.StatusBadRequest, "SAML login is not enabled")
		return
	}
	if h.SAML == nil {
		jsonError(w, http.StatusServiceUnavailable, "SAML provider not initialised")
		return
	}

	if err := h.SAML.Refresh(h.Settings, h.Secrets); err != nil {
		slog.Warn("SAML refresh error", "err", err)
		jsonError(w, http.StatusServiceUnavailable, "SAML provider configuration error")
		return
	}

	state, err := auth.GenerateState()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to generate state")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "gk_saml_state",
		Value:    state,
		Path:     "/",
		MaxAge:   300,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	redirectURL, err := h.SAML.MakeAuthenticationRequest(state)
	if err != nil {
		slog.Error("SAML AuthnRequest failed", "err", err)
		jsonError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// SAML Assertion Consumer Service endpoint.
func (h *AuthHandler) SAMLACS(w http.ResponseWriter, r *http.Request) {
	if h.SAML == nil || !h.SAML.IsConfigured() {
		http.Error(w, "SAML provider not configured", http.StatusServiceUnavailable)
		return
	}

	info, err := h.SAML.ParseResponse(r)
	if err != nil {
		slog.Error("SAML assertion validation failed", "err", err)
		metrics.LoginsFailed.Add(1)
		http.Redirect(w, r, "/?saml_error=assertion_failed", http.StatusFound)
		return
	}

	user, err := h.findOrCreateSAMLUser(info)
	if err != nil {
		slog.Error("SAML user provisioning failed", "err", err)
		metrics.LoginsFailed.Add(1)
		h.Audit.Log(&models.AuditEntry{
			Action:   "saml_login_failed",
			Username: info.Username,
			Detail:   err.Error(),
			SourceIP: r.RemoteAddr,
		})
		http.Redirect(w, r, "/?saml_error=provisioning_failed", http.StatusFound)
		return
	}

	token, err := h.Sessions.Create(user.ID, r.RemoteAddr, r.UserAgent())
	if err != nil {
		slog.Error("SAML session creation failed", "err", err)
		metrics.LoginsFailed.Add(1)
		http.Redirect(w, r, "/?saml_error=session_failed", http.StatusFound)
		return
	}
	metrics.LoginsSuccess.Add(1)

	h.Users.TouchLogin(user.ID)

	h.Audit.Log(&models.AuditEntry{
		Action:   "login",
		UserID:   user.ID,
		Username: user.Username,
		Detail:   "saml (" + info.NameID + ")",
		SourceIP: r.RemoteAddr,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "gk_saml_state",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(h.Sessions.Duration.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   h.UseTLS,
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

// Returns SP metadata XML for IdP configuration.
func (h *AuthHandler) SAMLMetadata(w http.ResponseWriter, r *http.Request) {
	if h.SAML == nil {
		http.Error(w, "SAML provider not configured", http.StatusServiceUnavailable)
		return
	}

	if err := h.SAML.Refresh(h.Settings, h.Secrets); err != nil {
		http.Error(w, "SAML provider configuration error", http.StatusServiceUnavailable)
		return
	}

	data, err := h.SAML.Metadata()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Write(data)
}

func (h *AuthHandler) findOrCreateSAMLUser(info *samlpkg.UserInfo) (*models.User, error) {
	resolvedGroups := info.Groups
	if h.GroupMappings != nil {
		mapped, err := h.GroupMappings.ResolveGroups(info.Groups)
		if err != nil {
			slog.Warn("SAML group mapping resolution failed", "err", err)
		} else {
			resolvedGroups = mapped
		}
	}

	user, err := h.Users.GetByAuthProviderAndSubject("saml", info.NameID)
	if err == nil {
		if user.Disabled {
			return nil, fmt.Errorf("account disabled")
		}
		user.Groups = strings.Join(resolvedGroups, ",")
		if info.DisplayName != "" {
			user.DisplayName = info.DisplayName
		}
		h.Users.Update(user)
		return user, nil
	}
	if err != sql.ErrNoRows {
		return nil, fmt.Errorf("lookup SAML user: %w", err)
	}

	autoProvision := false
	defaultRole := "user"
	if h.Settings != nil {
		autoProvision = h.Settings.Get(models.SettingSAMLAutoProvision, "false") == "true"
		defaultRole = h.Settings.Get(models.SettingSAMLDefaultRole, "user")
	}
	if !autoProvision {
		return nil, fmt.Errorf("user %s not provisioned and SAML auto-provisioning is disabled", info.Username)
	}

	newUser := &models.User{
		Username:     info.Username,
		DisplayName:  info.DisplayName,
		Role:         defaultRole,
		Groups:       strings.Join(resolvedGroups, ","),
		AuthProvider: "saml",
		OIDCSubject:  info.NameID,
	}
	if err := h.Users.CreateExternal(newUser, "saml"); err != nil {
		return nil, fmt.Errorf("auto-provision SAML user: %w", err)
	}
	slog.Info("auto-provisioned SAML user", "username", newUser.Username, "name_id", info.NameID, "role", defaultRole)
	return newUser, nil
}

func atoiSafe(s string) int {
	v, _ := strconv.Atoi(s)
	return v
}

func isPasswordExpired(changedAt string, maxAgeDays int) bool {
	t, err := time.Parse(time.RFC3339, changedAt)
	if err != nil {
		return false
	}
	return time.Since(t) > time.Duration(maxAgeDays)*24*time.Hour
}
