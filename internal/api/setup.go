package api

import (
	"io/fs"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/judsenb/gatekeeper/internal/auth"
	"github.com/judsenb/gatekeeper/internal/config"
	"github.com/judsenb/gatekeeper/internal/db"
	"github.com/judsenb/gatekeeper/internal/models"
)

type SetupResult struct {
	Config   *config.Config
	Database *db.DB
}

type SetupWizard struct {
	ConfigPath string
	Config     *config.Config
	Assets     fs.FS
	Done       chan *SetupResult
}

// no unsafe-inline for script-src — scripts are loaded from js/setup.js
func setupSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self'; "+
				"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "+
				"font-src 'self' https://fonts.gstatic.com; "+
				"connect-src 'self'; "+
				"img-src 'self' data:;")
		next.ServeHTTP(w, r)
	})
}

func (s *SetupWizard) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(setupSecurityHeaders)
	setupLimiter := newRateLimiter(20, 1*time.Minute)
	r.Use(RateLimitMiddleware(setupLimiter))

	r.Get("/api/setup/defaults", s.defaults)
	r.Post("/api/setup/test-db", s.testDB)
	r.Post("/api/setup/complete", s.complete)

	r.Get("/*", s.servePage)

	return r
}

// pre-fills the UI with sensible defaults (e.g. absolute SQLite path)
func (s *SetupWizard) defaults(w http.ResponseWriter, r *http.Request) {
	dbPath := s.Config.Database.Path
	if dbPath == "" {
		dbPath = "./gatekeeper.db"
	}
	jsonResponse(w, http.StatusOK, map[string]any{"db_path": dbPath})
}

func (s *SetupWizard) servePage(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "/" || path == "" {
		path = "/setup.html"
	}

	f, err := s.Assets.Open(path[1:])
	if err != nil {
		path = "/setup.html"
		f, err = s.Assets.Open("setup.html")
		if err != nil {
			http.Error(w, "setup page not found", http.StatusInternalServerError)
			return
		}
	}
	f.Close()

	if strings.HasSuffix(path, ".css") {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	} else if strings.HasSuffix(path, ".js") {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}

	http.ServeFileFS(w, r, s.Assets, path[1:])
}

// Validates DB connection without persisting anything.
func (s *SetupWizard) testDB(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Driver string `json:"db_driver"`
		Path   string `json:"db_path"`
		DSN    string `json:"db_dsn"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	driver := strings.TrimSpace(req.Driver)
	if driver != "sqlite" && driver != "postgres" {
		jsonError(w, http.StatusBadRequest, "driver must be 'sqlite' or 'postgres'")
		return
	}

	dsn := strings.TrimSpace(req.Path)
	if driver == "postgres" {
		dsn = strings.TrimSpace(req.DSN)
		if dsn == "" {
			jsonError(w, http.StatusBadRequest, "PostgreSQL connection string is required")
			return
		}
	}
	if dsn == "" {
		dsn = s.defaultDBPath()
	}

	database, err := db.Open(driver, dsn)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "connection failed: "+err.Error())
		return
	}
	database.Close()

	jsonResponse(w, http.StatusOK, map[string]any{"ok": true, "message": "Connection successful"})
}

// Creates DB, runs migrations, creates admin, logs you in. The whole shebang.
func (s *SetupWizard) complete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DBDriver         string `json:"db_driver"`
		DBPath           string `json:"db_path"`
		DBDSN            string `json:"db_dsn"`
		AdminUsername    string `json:"admin_username"`
		AdminDisplayName string `json:"admin_display_name"`
		AdminPassword    string `json:"admin_password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	driver := strings.TrimSpace(req.DBDriver)
	if driver != "sqlite" && driver != "postgres" {
		jsonError(w, http.StatusBadRequest, "driver must be 'sqlite' or 'postgres'")
		return
	}
	username := strings.TrimSpace(req.AdminUsername)
	if username == "" {
		jsonError(w, http.StatusBadRequest, "username is required")
		return
	}
	if err := auth.ValidatePassword(req.AdminPassword); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	dsn := strings.TrimSpace(req.DBPath)
	if driver == "postgres" {
		dsn = strings.TrimSpace(req.DBDSN)
	}
	if dsn == "" {
		dsn = s.defaultDBPath()
	}

	database, err := db.Open(driver, dsn)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "database connection failed: "+err.Error())
		return
	}

	if err := db.Migrate(database); err != nil {
		database.Close()
		jsonError(w, http.StatusInternalServerError, "migration failed: "+err.Error())
		return
	}

	userStore := &models.UserStore{DB: database}
	displayName := strings.TrimSpace(req.AdminDisplayName)
	if displayName == "" {
		displayName = "Administrator"
	}
	admin := &models.User{
		Username:     username,
		DisplayName:  displayName,
		Role:         "platform-admin",
		Groups:       "platform-admin",
		AuthProvider: "local",
	}
	if err := userStore.Create(admin, req.AdminPassword); err != nil {
		database.Close()
		jsonError(w, http.StatusInternalServerError, "failed to create admin user: "+err.Error())
		return
	}

	auditStore := &models.AuditStore{DB: database}
	auditStore.Log(&models.AuditEntry{
		Action:   "setup_complete",
		UserID:   admin.ID,
		Username: admin.Username,
		Detail:   "initial setup wizard completed",
		SourceIP: r.RemoteAddr,
	})

	// log the user in immediately so they don't have to re-auth after setup
	sessionStore := auth.NewSessionStore(database, s.Config.Auth.SessionDuration24h())
	token, err := sessionStore.Create(admin.ID, r.RemoteAddr, r.UserAgent())
	if err != nil {
		slog.Error("setup: failed to create session after setup", "err", err)
		jsonError(w, http.StatusInternalServerError, "failed to create session")
		return
	}
	userStore.TouchLogin(admin.ID)

	cfg := s.Config
	cfg.Database.Driver = driver
	if driver == "sqlite" {
		cfg.Database.Path = dsn
		cfg.Database.DSN = ""
	} else {
		cfg.Database.DSN = dsn
		cfg.Database.Path = ""
	}

	// Strip TLS paths back to config-dir-relative before saving so they
	// don't get double-joined on next startup.
	cfgDir := filepath.Dir(s.ConfigPath)
	if cfgDir != "" && cfgDir != "." {
		if rel, err := filepath.Rel(cfgDir, cfg.Server.TLSCert); err == nil {
			cfg.Server.TLSCert = rel
		}
		if rel, err := filepath.Rel(cfgDir, cfg.Server.TLSKey); err == nil {
			cfg.Server.TLSKey = rel
		}
	}

	if err := cfg.Save(s.ConfigPath); err != nil {
		slog.Warn("failed to save config file, continuing with in-memory config", "err", err)
	} else {
		slog.Info("config saved", "path", s.ConfigPath)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "gk_session",
		Value:    token,
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   cfg.Server.TLSCert != "",
	})

	jsonResponse(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": "Setup complete! Redirecting...",
	})

	go func() {
		s.Done <- &SetupResult{
			Config:   cfg,
			Database: database,
		}
	}()
}

// uses config path so we propose an absolute path in containers
func (s *SetupWizard) defaultDBPath() string {
	if s.Config != nil && s.Config.Database.Path != "" {
		return s.Config.Database.Path
	}
	return "./gatekeeper.db"
}
