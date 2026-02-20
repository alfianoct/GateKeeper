package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server        ServerConfig        `yaml:"server"`
	Database      DatabaseConfig      `yaml:"database"`
	Auth          AuthConfig          `yaml:"auth"`
	SSH           SSHConfig           `yaml:"ssh"`
	Audit         AuditConfig         `yaml:"audit"`
	Health        HealthConfig        `yaml:"health"`
	Secrets       SecretsConfig       `yaml:"secrets"`
	Observability ObservabilityConfig `yaml:"observability"`

	// 32-byte AES key, loaded at startup from secrets or env. never touches disk.
	EncryptionKey []byte `yaml:"-"`
}

type ObservabilityConfig struct {
	PrometheusEnabled bool   `yaml:"prometheus_enabled"`
	PrometheusListen  string `yaml:"prometheus_listen"` // e.g. ":9090"
}

type SecretsConfig struct {
	Backend    string `yaml:"backend"` // "vault", "env", or "none" (default)
	VaultAddr  string `yaml:"vault_addr"`
	VaultMount string `yaml:"vault_mount"` // e.g. "secret"
	VaultRole  string `yaml:"vault_role"`  // for Kubernetes auth
}

type ServerConfig struct {
	Listen         string `yaml:"listen"`
	HTTPRedirect   string `yaml:"http_redirect"` // e.g. ":8080" — listens for HTTP and redirects to HTTPS
	TLSCert        string `yaml:"tls_cert"`
	TLSKey         string `yaml:"tls_key"`
	DeploymentMode string `yaml:"deployment_mode"` // "single" (default) or "ha"
}

type DatabaseConfig struct {
	Driver string `yaml:"driver"` // "sqlite" or "postgres"; empty triggers setup wizard
	Path   string `yaml:"path"`   // SQLite file path
	DSN    string `yaml:"dsn"`    // PostgreSQL connection string
}

type AuthConfig struct {
	OIDCIssuer      string `yaml:"oidc_issuer"`
	ClientID        string `yaml:"client_id"`
	ClientSecret    string `yaml:"client_secret"`
	RedirectURL     string `yaml:"redirect_url"`
	SessionDuration string `yaml:"session_duration"`
}

type SSHConfig struct {
	HostKeyPath       string `yaml:"host_key_path"`
	DefaultPort       int    `yaml:"default_port"`
	ConnectTimeout    string `yaml:"connect_timeout"`
	KeepaliveInterval string `yaml:"keepalive_interval"`
	InactivityTimeout string `yaml:"inactivity_timeout"` // e.g. "30m"; close terminal after no input/output. "0" or empty = disabled.
}

// ConnectTimeoutDuration falls back to 10s if the value is garbage or missing.
func (s *SSHConfig) ConnectTimeoutDuration() time.Duration {
	if s.ConnectTimeout != "" {
		if d, err := time.ParseDuration(s.ConnectTimeout); err == nil && d > 0 {
			return d
		}
	}
	return 10 * time.Second
}

type AuditConfig struct {
	LogCommands    bool   `yaml:"log_commands"`
	RecordSessions bool   `yaml:"record_sessions"`
	RecordingPath  string `yaml:"recording_path"`
	RetentionDays  int    `yaml:"retention_days"`
}

type HealthConfig struct {
	CheckInterval string `yaml:"check_interval"`
	Timeout       string `yaml:"timeout"`
}

// Load reads YAML config with ${ENV_VAR} expansion. Missing file = defaults.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return defaults(), nil
		}
		return nil, err
	}

	expanded := os.Expand(string(data), func(key string) string {
		if v, ok := os.LookupEnv(key); ok {
			return v
		}
		return "${" + key + "}"
	})

	cfg := defaults()
	if err := yaml.Unmarshal([]byte(expanded), cfg); err != nil {
		return nil, err
	}
	applyServerDefaults(cfg)
	applySSHDefaults(cfg)
	applyEnvOverrides(cfg)

	return cfg, nil
}

func defaults() *Config {
	return &Config{
		Server: ServerConfig{
			Listen:       ":8443",
			HTTPRedirect: ":8080",
		},
		Database: DatabaseConfig{
			Driver: "",
			Path:   "./gatekeeper.db",
		},
		Auth: AuthConfig{
			SessionDuration: "24h",
		},
		SSH: SSHConfig{
			HostKeyPath:       "./gatekeeper_host_key",
			DefaultPort:       22,
			ConnectTimeout:    "10s",
			KeepaliveInterval: "30s",
			InactivityTimeout: "30m",
		},
		Audit: AuditConfig{
			LogCommands:    true,
			RecordSessions: true,
			RecordingPath:  "./recordings",
			RetentionDays:  90,
		},
		Health: HealthConfig{
			CheckInterval: "60s",
			Timeout:       "5s",
		},
		Secrets: SecretsConfig{
			Backend: "none",
		},
		Observability: ObservabilityConfig{
			PrometheusListen: ":9090",
		},
	}
}

func applyServerDefaults(cfg *Config) {
	if cfg.Server.Listen == "" {
		cfg.Server.Listen = ":8443"
	}
	if cfg.Server.HTTPRedirect == "" {
		cfg.Server.HTTPRedirect = ":8080"
	}
}

func applySSHDefaults(cfg *Config) {
	if cfg.SSH.ConnectTimeout == "" {
		cfg.SSH.ConnectTimeout = "10s"
	}
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("GK_LISTEN"); v != "" {
		cfg.Server.Listen = v
	}
	if v := os.Getenv("GK_DB_DRIVER"); v != "" {
		cfg.Database.Driver = v
	}
	if v := os.Getenv("GK_DB_PATH"); v != "" {
		cfg.Database.Path = v
	}
	if v := os.Getenv("GK_DB_DSN"); v != "" {
		cfg.Database.DSN = v
	}
	if v := os.Getenv("GK_OIDC_ISSUER"); v != "" {
		cfg.Auth.OIDCIssuer = v
	}
	if v := os.Getenv("GK_OIDC_CLIENT_ID"); v != "" {
		cfg.Auth.ClientID = v
	}
	if v := os.Getenv("GK_OIDC_SECRET"); v != "" {
		cfg.Auth.ClientSecret = v
	}
	if v := os.Getenv("GK_RECORDING_PATH"); v != "" {
		cfg.Audit.RecordingPath = v
	}
	if v := os.Getenv("GK_DEPLOYMENT_MODE"); v != "" {
		cfg.Server.DeploymentMode = v
	}
	if v := os.Getenv("GK_TLS_CERT"); v != "" {
		cfg.Server.TLSCert = v
	}
	if v := os.Getenv("GK_TLS_KEY"); v != "" {
		cfg.Server.TLSKey = v
	}
	if v := os.Getenv("GK_HOST_KEY_PATH"); v != "" {
		cfg.SSH.HostKeyPath = v
	}
	if v := os.Getenv("GK_HTTP_REDIRECT"); v != "" {
		cfg.Server.HTTPRedirect = v
	}
}

func (c *Config) Save(path string) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create config directory: %w", err)
		}
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(path, data, 0o600)
}

// SessionDuration24h defaults to 24h if the config value is bad or empty.
func (a *AuthConfig) SessionDuration24h() time.Duration {
	if a.SessionDuration != "" {
		if d, err := time.ParseDuration(a.SessionDuration); err == nil {
			return d
		}
	}
	return 24 * time.Hour
}
