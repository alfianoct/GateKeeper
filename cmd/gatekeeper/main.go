package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/judsenb/gatekeeper/internal/api"
	"github.com/judsenb/gatekeeper/internal/auth"
	"github.com/judsenb/gatekeeper/internal/config"
	gcrypto "github.com/judsenb/gatekeeper/internal/crypto"
	"github.com/judsenb/gatekeeper/internal/db"
	"github.com/judsenb/gatekeeper/internal/health"
	"github.com/judsenb/gatekeeper/internal/instance"
	"github.com/judsenb/gatekeeper/internal/metrics"
	"github.com/judsenb/gatekeeper/internal/models"
	"github.com/judsenb/gatekeeper/internal/secrets"
	sshpkg "github.com/judsenb/gatekeeper/internal/ssh"
	tlsgen "github.com/judsenb/gatekeeper/internal/tls"
	"github.com/judsenb/gatekeeper/web"
)

var version = "v0.1.1b"

// hot-swap handler so setup wizard can hand off to the real app without restarting the listener
type swappableHandler struct {
	mu      sync.RWMutex
	handler http.Handler
}

func (s *swappableHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	h := s.handler
	s.mu.RUnlock()
	h.ServeHTTP(w, r)
}

func (s *swappableHandler) Set(h http.Handler) {
	s.mu.Lock()
	s.handler = h
	s.mu.Unlock()
}

func main() {
	cfgPath := flag.String("config", "configs/gatekeeper.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		slog.Error("failed to load config", "path", *cfgPath, "err", err)
		os.Exit(1)
	}
	if err := cfg.Validate(); err != nil {
		slog.Error("invalid config", "err", err)
		os.Exit(1)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	instance.Init()
	slog.Info("GateKeeper starting",
		"version", version,
		"instance_id", instance.ID(),
		"deployment_mode", cfg.Server.DeploymentMode,
	)

	// encryption key setup
	secretsBackend := secrets.NewFromConfig(cfg.Secrets)
	keyProvider := gcrypto.NewKeyProvider(secretsBackend)
	if keyProvider.Enabled() {
		cfg.EncryptionKey = keyProvider.Key()
		slog.Info("encryption at rest enabled")
	} else {
		slog.Info("encryption at rest disabled (no GK_ENCRYPTION_KEY configured)")
	}

	// auto-generate self-signed TLS if nothing configured
	configDir := filepath.Dir(*cfgPath)
	if cfg.Server.TLSCert == "" || cfg.Server.TLSKey == "" {
		tlsDir := filepath.Join(configDir, "tls")
		cert, key, err := tlsgen.EnsureSelfSigned(tlsDir)
		if err != nil {
			slog.Error("failed to generate self-signed TLS", "err", err)
			os.Exit(1)
		}
		cfg.Server.TLSCert = cert
		cfg.Server.TLSKey = key
		slog.Info("using self-signed TLS cert", "path", cert)
	} else {
		if !filepath.IsAbs(cfg.Server.TLSCert) {
			cfg.Server.TLSCert = filepath.Join(configDir, cfg.Server.TLSCert)
		}
		if !filepath.IsAbs(cfg.Server.TLSKey) {
			cfg.Server.TLSKey = filepath.Join(configDir, cfg.Server.TLSKey)
		}
	}

	// figure out if we need the setup wizard
	needSetup := cfg.Database.Driver == ""
	if !needSetup {
		// sqlite file got deleted? wizard time again
		if cfg.Database.Driver == "sqlite" {
			dsn := cfg.Database.DSN
			if dsn == "" {
				dsn = cfg.Database.Path
			}
			if _, statErr := os.Stat(dsn); statErr != nil {
				needSetup = true
				slog.Info("database file missing, starting setup wizard")
			}
		}
	} else {
		// no driver but db file exists? just use it
		if _, statErr := os.Stat(cfg.Database.Path); statErr == nil {
			cfg.Database.Driver = "sqlite"
			needSetup = false
			slog.Info("found existing database, assuming SQLite")
		}
	}

	addr := cfg.Server.Listen
	rootHandler := &swappableHandler{
		handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "starting...", http.StatusServiceUnavailable)
		}),
	}

	// TLS with hot-reload
	certReloader, err := tlsgen.NewCertReloader(cfg.Server.TLSCert, cfg.Server.TLSKey)
	if err != nil {
		slog.Error("failed to load TLS certificate", "err", err)
		os.Exit(1)
	}
	certReloader.Watch(30 * time.Second)
	defer certReloader.Stop()

	srv := &http.Server{
		Addr:      addr,
		Handler:   rootHandler,
		TLSConfig: certReloader.TLSConfig(),
	}

	// empty strings here because GetCertificate callback handles it
	go func() {
		slog.Info("GateKeeper listening", "addr", "https://"+addr)
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	httpAddr := cfg.Server.HTTPRedirect
	go func() {
		redirect := http.NewServeMux()
		redirect.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			target := "https://" + r.Host + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		})
		slog.Info("HTTP→HTTPS redirect", "addr", httpAddr)
		if err := http.ListenAndServe(httpAddr, redirect); err != nil && err != http.ErrServerClosed {
			slog.Warn("HTTP redirect listener failed", "err", err)
		}
	}()

	// prometheus (unauthenticated on purpose — restrict by network if you care)
	if cfg.Observability.PrometheusEnabled {
		promListen := cfg.Observability.PrometheusListen
		if promListen == "" {
			promListen = ":9090"
		}
		go func() {
			mux := http.NewServeMux()
			mux.Handle("/", metrics.PrometheusHandler())
			slog.Info("Prometheus metrics", "addr", promListen)
			if err := http.ListenAndServe(promListen, mux); err != nil && err != http.ErrServerClosed {
				slog.Warn("Prometheus listener failed", "err", err)
			}
		}()
	}

	var database *db.DB

	if needSetup {
		slog.Info("no database configured, starting setup wizard")

		wizard := &api.SetupWizard{
			ConfigPath: *cfgPath,
			Config:     cfg,
			Assets:     web.Assets,
			Done:       make(chan *api.SetupResult, 1),
		}

		rootHandler.Set(wizard.Router())
		slog.Info("setup wizard ready", "addr", "https://"+addr)
		result := <-wizard.Done
		cfg = result.Config
		database = result.Database
		slog.Info("setup complete, switching to main application")
	} else {
		dsn := cfg.Database.DSN
		if cfg.Database.Driver == "sqlite" && dsn == "" {
			dsn = cfg.Database.Path
		}

		database, err = db.Open(cfg.Database.Driver, dsn)
		if err != nil {
			slog.Error("failed to open database", "err", err)
			os.Exit(1)
		}

		if err := db.Migrate(database); err != nil {
			slog.Error("failed to run migrations", "err", err)
			os.Exit(1)
		}
		slog.Info("database initialized")
	}

	defer database.Close()

	sshMgr := sshpkg.NewSessionManager()
	sessionDuration := 24 * time.Hour
	if cfg.Auth.SessionDuration != "" {
		if d, err := time.ParseDuration(cfg.Auth.SessionDuration); err == nil {
			sessionDuration = d
		}
	}

	// hourly cleanup of stale ssh session records
	sessionStore := &models.SessionStore{DB: database}
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			n, err := sessionStore.CleanupStale(24 * time.Hour)
			if err != nil {
				slog.Warn("session cleanup error", "err", err)
			} else if n > 0 {
				slog.Info("cleaned up stale sessions", "count", n)
			}
		}
	}()

	// same deal but for login sessions and dangling mfa tokens
	authSessionStore := auth.NewSessionStore(database, sessionDuration)
	mfaPendingStore := &auth.MFAPendingStore{DB: database}
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			if err := authSessionStore.Cleanup(); err != nil {
				slog.Warn("auth session cleanup error", "err", err)
			}
			if err := mfaPendingStore.Cleanup(); err != nil {
				slog.Warn("mfa pending cleanup error", "err", err)
			}
		}
	}()

	hostStore := &models.HostStore{DB: database}
	healthChecker := health.NewChecker(hostStore, cfg.Health)
	healthChecker.Start()

	// swap in the real router — listener is already up
	router := api.NewRouter(database, cfg, web.Assets, sshMgr, certReloader)
	rootHandler.Set(router)
	slog.Info("GateKeeper ready", "addr", "https://"+addr)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for {
		sig := <-sigCh
		if sig == syscall.SIGHUP {
			slog.Info("received SIGHUP, reloading TLS certificate")
			if err := certReloader.Reload(); err != nil {
				slog.Error("TLS reload failed on SIGHUP", "err", err)
			}
			continue
		}
		fmt.Printf("\n[INFO] received %v, shutting down...\n", sig)
		healthChecker.Stop()
		sshMgr.KillAll()
		srv.Close()
		break
	}

	slog.Info("GateKeeper stopped")
}
