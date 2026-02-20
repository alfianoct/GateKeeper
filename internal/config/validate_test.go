package config

import (
	"strings"
	"testing"
)

func validConfig() *Config {
	return &Config{
		Server:   ServerConfig{Listen: ":8443", HTTPRedirect: ":8080", DeploymentMode: "single"},
		Database: DatabaseConfig{Driver: "sqlite", Path: "./test.db"},
		SSH:      SSHConfig{DefaultPort: 22, ConnectTimeout: "10s", KeepaliveInterval: "30s"},
		Audit:    AuditConfig{RetentionDays: 90},
		Health:   HealthConfig{CheckInterval: "60s", Timeout: "5s"},
	}
}

func TestValidate_Defaults(t *testing.T) {
	cfg := validConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid config should pass: %v", err)
	}
}

func TestValidate_InvalidDeploymentMode(t *testing.T) {
	cfg := validConfig()
	cfg.Server.DeploymentMode = "banana"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for deployment_mode=banana")
	}
	if !strings.Contains(err.Error(), "banana") {
		t.Errorf("error should mention 'banana': %v", err)
	}
}

func TestValidate_HAWithSQLite(t *testing.T) {
	cfg := validConfig()
	cfg.Server.DeploymentMode = "ha"
	cfg.Database.Driver = "sqlite"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("HA mode with sqlite should be rejected")
	}
}

func TestValidate_InvalidDBDriver(t *testing.T) {
	cfg := validConfig()
	cfg.Database.Driver = "mysql"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for driver=mysql")
	}
	if !strings.Contains(err.Error(), "mysql") {
		t.Errorf("error should mention 'mysql': %v", err)
	}
}

func TestValidate_PostgresNoDSN(t *testing.T) {
	cfg := validConfig()
	cfg.Database.Driver = "postgres"
	cfg.Database.DSN = ""
	cfg.Database.Path = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("postgres with empty DSN should fail")
	}
}

func TestValidate_SQLiteNoPath(t *testing.T) {
	cfg := validConfig()
	cfg.Database.Driver = "sqlite"
	cfg.Database.Path = ""
	cfg.Database.DSN = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("sqlite with no path or DSN should fail")
	}
}

func TestValidate_InvalidSessionDuration(t *testing.T) {
	cfg := validConfig()
	cfg.Auth.SessionDuration = "banana"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for session_duration=banana")
	}
}

func TestValidate_ValidSessionDuration(t *testing.T) {
	cfg := validConfig()
	cfg.Auth.SessionDuration = "12h"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("12h should be valid: %v", err)
	}
}

func TestValidate_SSHPortOutOfRange(t *testing.T) {
	cfg := validConfig()
	cfg.SSH.DefaultPort = 99999
	err := cfg.Validate()
	if err == nil {
		t.Fatal("port 99999 should be rejected")
	}
}

func TestValidate_InvalidConnectTimeout(t *testing.T) {
	cfg := validConfig()
	cfg.SSH.ConnectTimeout = "banana"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for connect_timeout=banana")
	}
}

func TestValidate_NegativeRetention(t *testing.T) {
	cfg := validConfig()
	cfg.Audit.RetentionDays = -1
	err := cfg.Validate()
	if err == nil {
		t.Fatal("negative retention_days should fail")
	}
}

func TestValidate_InvalidHealthInterval(t *testing.T) {
	cfg := validConfig()
	cfg.Health.CheckInterval = "banana"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for check_interval=banana")
	}
}
