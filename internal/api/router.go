package api

import (
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/judsenb/gatekeeper/internal/audit"
	"github.com/judsenb/gatekeeper/internal/auth"
	samlpkg "github.com/judsenb/gatekeeper/internal/auth/saml"
	"github.com/judsenb/gatekeeper/internal/config"
	"github.com/judsenb/gatekeeper/internal/db"
	"github.com/judsenb/gatekeeper/internal/models"
	"github.com/judsenb/gatekeeper/internal/secrets"
	sshpkg "github.com/judsenb/gatekeeper/internal/ssh"
	tlsgen "github.com/judsenb/gatekeeper/internal/tls"
)

type Stores struct {
	Hosts          *models.HostStore
	Sessions       *models.SessionStore
	Audit          *models.AuditStore
	Keys           *models.KeyStore
	Users          *models.UserStore
	Settings       *models.SettingStore
	HostKeys       *models.HostKeyStore
	Groups         *models.GroupStore
	GroupMappings  *models.GroupMappingStore
	AccessRequests *models.AccessRequestStore
	AccessWindows  *models.AccessWindowStore
	SSHManager     *sshpkg.SessionManager
	AuthSessions   *auth.SessionStore
	Config         *config.Config
}

// certReloader can be nil during setup wizard — health check copes
func NewRouter(database *db.DB, cfg *config.Config, webFS fs.FS, sshMgr *sshpkg.SessionManager, certReloader *tlsgen.CertReloader) http.Handler {
	sessionDuration := 24 * time.Hour
	if cfg.Auth.SessionDuration != "" {
		if d, err := time.ParseDuration(cfg.Auth.SessionDuration); err == nil {
			sessionDuration = d
		}
	}

	sessionStore := auth.NewSessionStore(database, sessionDuration)

	// lazy — discovers endpoints on first use
	oidcProvider := auth.NewOIDCProvider()
	samlProvider := samlpkg.NewProvider()

	auditDispatcher := audit.NewDispatcher()

	ipRuleStore := &models.IPRuleStore{DB: database}

	stores := &Stores{
		Hosts:          &models.HostStore{DB: database},
		Sessions:       &models.SessionStore{DB: database},
		Audit:          &models.AuditStore{DB: database, Dispatcher: auditDispatcher},
		Keys:           &models.KeyStore{DB: database},
		Users:          &models.UserStore{DB: database},
		Settings:       &models.SettingStore{DB: database, EncryptionKey: cfg.EncryptionKey},
		HostKeys:       &models.HostKeyStore{DB: database},
		Groups:         &models.GroupStore{DB: database},
		GroupMappings:  &models.GroupMappingStore{DB: database},
		AccessRequests: &models.AccessRequestStore{DB: database},
		AccessWindows:  &models.AccessWindowStore{DB: database},
		SSHManager:     sshMgr,
		AuthSessions:   sessionStore,
		Config:         cfg,
	}

	secretsBackend := secrets.NewFromConfig(cfg.Secrets)

	ConfigureAuditExporters(auditDispatcher, stores.Settings)

	authMode := stores.Settings.Get(models.SettingAuthMode, "local")
	if authMode == "oidc" || authMode == "local+oidc" {
		if err := oidcProvider.Refresh(stores.Settings, secretsBackend); err != nil {
			slog.Warn("OIDC provider init failed, will retry on first login", "err", err)
		} else {
			slog.Info("OIDC provider initialised")
		}
	}

	if authMode == "saml" || authMode == "local+saml" {
		if err := samlProvider.Refresh(stores.Settings, secretsBackend); err != nil {
			slog.Warn("SAML provider init failed, will retry on first login", "err", err)
		} else {
			slog.Info("SAML provider initialised")
		}
	}

	mfaPendingStore := &auth.MFAPendingStore{DB: database}

	authHandler := &AuthHandler{
		Users:          stores.Users,
		Groups:         stores.Groups,
		Sessions:       sessionStore,
		SSHSessions:    stores.Sessions,
		MFAPending:     mfaPendingStore,
		Audit:          stores.Audit,
		Settings:       stores.Settings,
		GroupMappings:  stores.GroupMappings,
		OIDC:           oidcProvider,
		SAML:           samlProvider,
		Secrets:        secretsBackend,
		UseTLS:         cfg.Server.TLSCert != "",
		DeploymentMode: cfg.Server.DeploymentMode,
	}

	mfaHandler := &MFAHandler{
		Users:      stores.Users,
		Sessions:   sessionStore,
		MFAPending: mfaPendingStore,
		Audit:      stores.Audit,
		Settings:   stores.Settings,
		UseTLS:     cfg.Server.TLSCert != "",
	}

	r := chi.NewRouter()

	r.Use(chiMiddleware.RequestID)
	r.Use(chiMiddleware.RealIP)
	r.Use(chiMiddleware.Logger)
	r.Use(chiMiddleware.Recoverer)
	r.Use(SecurityHeaders)
	r.Use(GlobalIPFilter(ipRuleStore, stores.Audit))

	healthHandler := &HealthHandler{DB: database, DeploymentMode: cfg.Server.DeploymentMode, TLS: certReloader}
	r.Get("/health", healthHandler.Liveness)
	r.Get("/ready", healthHandler.Readiness)

	// rate limit login + OIDC to prevent state exhaustion and redirect spam
	loginLimiter := newRateLimiter(10, 1*time.Minute)
	authLimiter := newRateLimiter(30, 1*time.Minute)

	r.With(RateLimitMiddleware(loginLimiter)).Post("/auth/login", authHandler.Login)
	r.Post("/auth/logout", authHandler.Logout)
	r.Get("/auth/providers", authHandler.GetAuthProviders)
	r.With(RateLimitMiddleware(authLimiter)).Get("/auth/oidc", authHandler.OIDCRedirect)
	r.With(RateLimitMiddleware(authLimiter)).Get("/auth/oidc/callback", authHandler.OIDCCallback)
	r.With(RateLimitMiddleware(authLimiter)).Get("/auth/saml", authHandler.SAMLRedirect)
	r.Post("/auth/saml/acs", authHandler.SAMLACS)
	r.Get("/auth/saml/metadata", authHandler.SAMLMetadata)
	// unauthenticated — uses pending MFA token, not a real session
	r.With(RateLimitMiddleware(loginLimiter)).Post("/auth/mfa/verify", mfaHandler.Verify)
	r.With(RateLimitMiddleware(loginLimiter)).Post("/auth/mfa/recover", mfaHandler.Recover)

	r.Route("/api", func(r chi.Router) {
		r.Use(AuthMiddleware(sessionStore, stores.Users))

		r.Get("/me", authHandler.GetCurrentUser)
		r.Get("/me/mfa", mfaHandler.GetMFAStatus)
		r.Post("/me/mfa/enroll", mfaHandler.Enroll)
		r.Post("/me/mfa/confirm", mfaHandler.Confirm)
		r.Post("/me/mfa/disable", mfaHandler.Disable)
		r.Post("/me/password", mfaHandler.ChangePassword)
		r.Get("/hosts", stores.ListHosts)
		r.Get("/hosts/{id}", stores.GetHost)
		r.Get("/hosts/{id}/active-session", stores.GetHostActiveSession)

		r.Group(func(r chi.Router) {
			r.Use(RequirePermission(stores.Groups, "view_sessions"))
			r.Get("/sessions", stores.ListActiveSessions)
			r.Get("/sessions/history", stores.ListSessionHistory)
			r.Get("/sessions/{id}/recording", stores.GetSessionRecording)
		})

		auditExportHandler := &AuditExportHandler{Audit: stores.Audit, Settings: stores.Settings}
		dashHandler := &DashboardHandler{
			Hosts:         stores.Hosts,
			Sessions:      stores.Sessions,
			Audit:         stores.Audit,
			Users:         stores.Users,
			Settings:      stores.Settings,
			TLS:           certReloader,
			DBDriver:      cfg.Database.Driver,
			Mode:          cfg.Server.DeploymentMode,
			EncryptionKey: cfg.EncryptionKey,
		}
		r.Group(func(r chi.Router) {
			r.Use(RequirePermission(stores.Groups, "view_audit"))
			r.Get("/audit", stores.ListAuditLog)
			r.Get("/audit/export", auditExportHandler.BulkExport)
			r.Post("/audit/test-webhook", auditExportHandler.TestWebhook)
			r.Get("/dashboard", dashHandler.GetDashboard)
		})

		r.Group(func(r chi.Router) {
			r.Use(RequirePermission(stores.Groups, "manage_sessions"))
			r.Delete("/sessions/{id}", stores.KillSession)
		})
		r.Group(func(r chi.Router) {
			r.Use(RequirePermission(stores.Groups, "manage_hosts"))
			r.Post("/hosts", stores.CreateHost)
			r.Put("/hosts/{id}", stores.UpdateHost)
			r.Delete("/hosts/{id}", stores.DeleteHost)
			r.Post("/hosts/{id}/toggle-disabled", stores.ToggleHostDisabled)
		})
		r.Group(func(r chi.Router) {
			r.Use(RequirePermission(stores.Groups, "manage_keys"))
			r.Get("/keys", stores.ListKeys)
			r.Post("/keys", stores.CreateKey)
			r.Delete("/keys/{id}", stores.DeleteKey)
		})
		r.Group(func(r chi.Router) {
			r.Use(RequirePermission(stores.Groups, "manage_users"))
			r.Get("/users", stores.ListUsers)
			r.Post("/users", stores.CreateUser)
			r.Put("/users/{id}", stores.UpdateUser)
			r.Delete("/users/{id}", stores.DeleteUser)
			r.Delete("/users/{id}/mfa", mfaHandler.AdminReset)
		})
		r.Group(func(r chi.Router) {
			r.Use(RequirePermission(stores.Groups, "manage_groups"))
			r.Get("/groups", stores.ListGroups)
			r.Post("/groups", stores.CreateGroup)
			r.Put("/groups/{id}", stores.UpdateGroup)
			r.Delete("/groups/{id}", stores.DeleteGroup)
			r.Get("/group-mappings", stores.ListGroupMappings)
			r.Post("/group-mappings", stores.CreateGroupMapping)
			r.Delete("/group-mappings/{id}", stores.DeleteGroupMapping)
		})
		r.Group(func(r chi.Router) {
			r.Use(RequirePermission(stores.Groups, "manage_settings"))
			settingsHandler := &SettingsHandler{Settings: stores.Settings, Audit: stores.Audit, Dispatcher: auditDispatcher}
			r.Get("/settings", settingsHandler.GetSettings)
			r.Put("/settings", settingsHandler.UpdateSettings)
			ipRuleHandler := &IPRuleHandler{IPRules: ipRuleStore, Audit: stores.Audit}
			r.Get("/ip-rules", ipRuleHandler.ListRules)
			r.Post("/ip-rules", ipRuleHandler.CreateRule)
			r.Delete("/ip-rules/{id}", ipRuleHandler.DeleteRule)
			encHandler := &EncryptionHandler{
				Settings:     stores.Settings,
				Sessions:     stores.Sessions,
				Audit:        stores.Audit,
				RecordingDir: cfg.Audit.RecordingPath,
				GetKey:       func() []byte { return cfg.EncryptionKey },
			}
			r.Get("/encryption/status", encHandler.GetStatus)
			r.Post("/encryption/rotate", encHandler.RotateKey)
			r.Post("/encryption/encrypt-existing", encHandler.EncryptExisting)
		})
		// anyone authed can create, but only manage_sessions can approve/reject
		r.Post("/access-requests", stores.CreateAccessRequest)
		r.Group(func(r chi.Router) {
			r.Use(RequirePermission(stores.Groups, "manage_sessions"))
			r.Get("/access-requests", stores.ListAccessRequests)
			r.Post("/access-requests/{id}/approve", stores.ApproveAccessRequest)
			r.Post("/access-requests/{id}/reject", stores.RejectAccessRequest)
		})
		r.Group(func(r chi.Router) {
			r.Use(RequirePermission(stores.Groups, "manage_hosts"))
			r.Get("/access-windows", stores.ListAccessWindows)
			r.Post("/access-windows", stores.CreateAccessWindow)
			r.Delete("/access-windows/{id}", stores.DeleteAccessWindow)
		})
	})

	wsHandler := &SSHWebSocketHandler{
		Hosts:          stores.Hosts,
		Sessions:       stores.Sessions,
		Audit:          stores.Audit,
		Groups:         stores.Groups,
		Keys:           stores.Keys,
		HostKeys:       stores.HostKeys,
		SSHManager:     sshMgr,
		Config:         cfg,
		AccessRequests: stores.AccessRequests,
		AccessWindows:  stores.AccessWindows,
		IPRules:        ipRuleStore,
		Settings:       stores.Settings,
		EncryptionKey:  cfg.EncryptionKey,
	}
	watchHandler := &WatchSessionHandler{
		SSHManager: sshMgr,
		Audit:      stores.Audit,
	}
	r.Group(func(r chi.Router) {
		r.Use(AuthMiddleware(sessionStore, stores.Users))
		r.Get("/ws/ssh/{hostId}", wsHandler.ServeHTTP)
	})
	r.Group(func(r chi.Router) {
		r.Use(AuthMiddleware(sessionStore, stores.Users))
		r.Use(RequirePermission(stores.Groups, "view_sessions"))
		r.Get("/ws/watch/{sessionId}", watchHandler.ServeHTTP)
	})

	fileServer := http.FileServer(http.FS(webFS))
	r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" {
			path = "/index.html"
		}

		f, err := webFS.Open(path[1:]) // strip leading /
		if err != nil {
			// SPA fallback
			r.URL.Path = "/"
			fileServer.ServeHTTP(w, r)
			return
		}
		f.Close()

		fileServer.ServeHTTP(w, r)
	})

	return r
}
