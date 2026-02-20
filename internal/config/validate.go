package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// Validate catches dumb config mistakes. Call after Load.
func (c *Config) Validate() error {
	if err := c.validateServer(); err != nil {
		return err
	}
	if err := c.validateDatabase(); err != nil {
		return err
	}
	if err := c.validateAuth(); err != nil {
		return err
	}
	if err := c.validateSSH(); err != nil {
		return err
	}
	if err := c.validateAudit(); err != nil {
		return err
	}
	if err := c.validateHealth(); err != nil {
		return err
	}
	return nil
}

func (c *Config) validateServer() error {
	if c.Server.Listen == "" {
		c.Server.Listen = ":8443"
	}

	mode := c.Server.DeploymentMode
	if mode == "" {
		mode = "single"
		c.Server.DeploymentMode = mode
	}
	if mode != "single" && mode != "ha" {
		return fmt.Errorf("server: deployment_mode must be %q or %q, got %q", "single", "ha", mode)
	}

	if mode == "ha" {
		if c.Database.Driver == "sqlite" {
			return fmt.Errorf("HA mode requires database.driver=postgres (sqlite is single-node only)")
		}
		if os.Getenv("GK_INSTANCE_ID") == "" {
			slog.Warn("HA mode: GK_INSTANCE_ID not set; a random ID will be generated — set it explicitly for stable node identity")
		}
		recPath := c.Audit.RecordingPath
		if recPath != "" && !filepath.IsAbs(recPath) {
			slog.Warn("HA mode: recording_path is relative — ensure it points to shared storage for cross-node playback", "path", recPath)
		}
	}

	return nil
}

func (c *Config) validateDatabase() error {
	d := &c.Database
	if d.Driver == "" {
		return nil // setup wizard will run
	}
	switch d.Driver {
	case "sqlite":
		if d.Path == "" && d.DSN == "" {
			return fmt.Errorf("database: sqlite requires path or dsn")
		}
		if d.Path == "" {
			d.Path = d.DSN
		}
	case "postgres":
		if d.DSN == "" {
			return fmt.Errorf("database: postgres requires dsn")
		}
	default:
		return fmt.Errorf("database: driver must be %q or %q, got %q", "sqlite", "postgres", d.Driver)
	}
	return nil
}

func (c *Config) validateAuth() error {
	if c.Auth.SessionDuration == "" {
		return nil
	}
	if _, err := time.ParseDuration(c.Auth.SessionDuration); err != nil {
		return fmt.Errorf("auth: invalid session_duration %q: %w", c.Auth.SessionDuration, err)
	}
	return nil
}

func (c *Config) validateSSH() error {
	p := c.SSH.DefaultPort
	if p < 1 || p > 65535 {
		return fmt.Errorf("ssh: default_port must be 1-65535, got %d", p)
	}
	if c.SSH.ConnectTimeout != "" {
		if _, err := time.ParseDuration(c.SSH.ConnectTimeout); err != nil {
			return fmt.Errorf("ssh: invalid connect_timeout %q: %w", c.SSH.ConnectTimeout, err)
		}
	}
	if c.SSH.KeepaliveInterval != "" {
		if _, err := time.ParseDuration(c.SSH.KeepaliveInterval); err != nil {
			return fmt.Errorf("ssh: invalid keepalive_interval %q: %w", c.SSH.KeepaliveInterval, err)
		}
	}
	if c.SSH.InactivityTimeout != "" && c.SSH.InactivityTimeout != "0" {
		if _, err := time.ParseDuration(c.SSH.InactivityTimeout); err != nil {
			return fmt.Errorf("ssh: invalid inactivity_timeout %q: %w", c.SSH.InactivityTimeout, err)
		}
	}
	return nil
}

func (c *Config) validateAudit() error {
	if c.Audit.RetentionDays < 0 {
		return fmt.Errorf("audit: retention_days must be >= 0, got %d", c.Audit.RetentionDays)
	}
	return nil
}

func (c *Config) validateHealth() error {
	if c.Health.CheckInterval != "" {
		if _, err := time.ParseDuration(c.Health.CheckInterval); err != nil {
			return fmt.Errorf("health: invalid check_interval %q: %w", c.Health.CheckInterval, err)
		}
	}
	if c.Health.Timeout != "" {
		if _, err := time.ParseDuration(c.Health.Timeout); err != nil {
			return fmt.Errorf("health: invalid timeout %q: %w", c.Health.Timeout, err)
		}
	}
	return nil
}
