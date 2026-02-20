package db

import (
	"fmt"
	"log/slog"
)

// pg overrides sqlite SQL when set; otherwise sqlite is used for both
type migration struct {
	name   string
	sqlite string
	pg     string
}

var migrations = []migration{
	{
		name: "001_create_hosts",
		sqlite: `CREATE TABLE IF NOT EXISTS hosts (
			id         TEXT PRIMARY KEY,
			name       TEXT NOT NULL UNIQUE,
			hostname   TEXT NOT NULL,
			port       INTEGER NOT NULL DEFAULT 22,
			os         TEXT NOT NULL DEFAULT '',
			vlan       TEXT NOT NULL DEFAULT '',
			subnet     TEXT NOT NULL DEFAULT '',
			protocols  TEXT NOT NULL DEFAULT 'SSH',
			online     INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
	},
	{
		name: "002_create_sessions",
		sqlite: `CREATE TABLE IF NOT EXISTS sessions (
			id           TEXT PRIMARY KEY,
			user_id      TEXT NOT NULL DEFAULT '',
			username     TEXT NOT NULL,
			host_id      TEXT NOT NULL REFERENCES hosts(id),
			host_name    TEXT NOT NULL,
			host_addr    TEXT NOT NULL,
			protocol     TEXT NOT NULL DEFAULT 'SSH',
			connected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			closed_at    TEXT,
			bytes_tx     INTEGER NOT NULL DEFAULT 0,
			bytes_rx     INTEGER NOT NULL DEFAULT 0,
			recording    TEXT NOT NULL DEFAULT ''
		);`,
	},
	{
		name: "003_create_audit_log",
		sqlite: `CREATE TABLE IF NOT EXISTS audit_log (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			action     TEXT NOT NULL,
			user_id    TEXT NOT NULL DEFAULT '',
			username   TEXT NOT NULL DEFAULT '',
			target_id  TEXT NOT NULL DEFAULT '',
			target     TEXT NOT NULL DEFAULT '',
			detail     TEXT NOT NULL DEFAULT '',
			source_ip  TEXT NOT NULL DEFAULT '',
			session_id TEXT NOT NULL DEFAULT ''
		);`,
		pg: `CREATE TABLE IF NOT EXISTS audit_log (
			id         BIGSERIAL PRIMARY KEY,
			timestamp  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			action     TEXT NOT NULL,
			user_id    TEXT NOT NULL DEFAULT '',
			username   TEXT NOT NULL DEFAULT '',
			target_id  TEXT NOT NULL DEFAULT '',
			target     TEXT NOT NULL DEFAULT '',
			detail     TEXT NOT NULL DEFAULT '',
			source_ip  TEXT NOT NULL DEFAULT '',
			session_id TEXT NOT NULL DEFAULT ''
		);`,
	},
	{
		name: "004_create_access_rules",
		sqlite: `CREATE TABLE IF NOT EXISTS access_rules (
			id            TEXT PRIMARY KEY,
			group_name    TEXT NOT NULL,
			allowed_hosts TEXT NOT NULL DEFAULT '*/*',
			protocols     TEXT NOT NULL DEFAULT 'SSH',
			access_level  TEXT NOT NULL DEFAULT 'full'
		);`,
	},
	{
		name: "005_create_ssh_keys",
		sqlite: `CREATE TABLE IF NOT EXISTS ssh_keys (
			id          TEXT PRIMARY KEY,
			name        TEXT NOT NULL,
			key_type    TEXT NOT NULL DEFAULT 'ED25519',
			public_key  TEXT NOT NULL,
			fingerprint TEXT NOT NULL,
			user_id     TEXT NOT NULL DEFAULT '',
			is_system   INTEGER NOT NULL DEFAULT 0,
			added_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_used_at TEXT
		);`,
	},
	{
		name: "006_create_schema_migrations",
		sqlite: `CREATE TABLE IF NOT EXISTS schema_migrations (
			name       TEXT PRIMARY KEY,
			applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
	},
	{
		name: "007_create_users",
		sqlite: `CREATE TABLE IF NOT EXISTS users (
			id            TEXT PRIMARY KEY,
			username      TEXT NOT NULL UNIQUE,
			display_name  TEXT NOT NULL DEFAULT '',
			password_hash TEXT NOT NULL DEFAULT '',
			role          TEXT NOT NULL DEFAULT 'user',
			groups_csv    TEXT NOT NULL DEFAULT '',
			auth_provider TEXT NOT NULL DEFAULT 'local',
			oidc_subject  TEXT NOT NULL DEFAULT '',
			disabled      INTEGER NOT NULL DEFAULT 0,
			created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_login_at TEXT
		);`,
	},
	{
		name: "008_create_auth_sessions",
		sqlite: `CREATE TABLE IF NOT EXISTS auth_sessions (
			token_hash TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL REFERENCES users(id),
			ip         TEXT NOT NULL DEFAULT '',
			user_agent TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at TEXT NOT NULL
		);`,
	},
	{
		name: "009_create_settings",
		sqlite: `CREATE TABLE IF NOT EXISTS settings (
			key        TEXT PRIMARY KEY,
			value      TEXT NOT NULL DEFAULT '',
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
	},
	{
		name:   "011_add_host_ssh_user",
		sqlite: `ALTER TABLE hosts ADD COLUMN ssh_user TEXT NOT NULL DEFAULT '';`,
	},
	{
		name:   "012_add_host_ssh_auth_method",
		sqlite: `ALTER TABLE hosts ADD COLUMN ssh_auth_method TEXT NOT NULL DEFAULT 'password';`,
	},
	{
		name:   "013_add_host_ssh_password",
		sqlite: `ALTER TABLE hosts ADD COLUMN ssh_password TEXT NOT NULL DEFAULT '';`,
	},
	{
		name:   "014_add_host_ssh_key_id",
		sqlite: `ALTER TABLE hosts ADD COLUMN ssh_key_id TEXT NOT NULL DEFAULT '';`,
	},
	{
		name: "010_create_host_keys",
		sqlite: `CREATE TABLE IF NOT EXISTS host_keys (
			host_id    TEXT NOT NULL,
			key_type   TEXT NOT NULL,
			public_key TEXT NOT NULL,
			first_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (host_id, key_type)
		);`,
	},
	{
		name: "015_create_groups",
		sqlite: `CREATE TABLE IF NOT EXISTS groups (
			id          TEXT PRIMARY KEY,
			name        TEXT NOT NULL UNIQUE,
			description TEXT NOT NULL DEFAULT '',
			permissions TEXT NOT NULL DEFAULT '',
			created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
	},
	{
		name: "016_create_group_mappings",
		sqlite: `CREATE TABLE IF NOT EXISTS group_mappings (
			id              TEXT PRIMARY KEY,
			external_group  TEXT NOT NULL,
			gatekeeper_group TEXT NOT NULL,
			created_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
	},
	{
		name:   "017_add_groups_allowed_hosts",
		sqlite: `ALTER TABLE groups ADD COLUMN allowed_hosts TEXT NOT NULL DEFAULT '*';`,
	},
	{
		name:   "018_add_hosts_disabled",
		sqlite: `ALTER TABLE hosts ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0;`,
	},
	{
		name:   "019_add_ssh_key_private_key",
		sqlite: `ALTER TABLE ssh_keys ADD COLUMN private_key TEXT NOT NULL DEFAULT '';`,
	},
	{
		name:   "020_drop_access_rules",
		sqlite: `DROP TABLE IF EXISTS access_rules;`,
	},
	{
		name:   "021_audit_log_reason",
		sqlite: `ALTER TABLE audit_log ADD COLUMN reason TEXT NOT NULL DEFAULT '';`,
		pg:     `ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS reason TEXT NOT NULL DEFAULT '';`,
	},
	{
		name:   "022_sessions_reason",
		sqlite: `ALTER TABLE sessions ADD COLUMN reason TEXT NOT NULL DEFAULT '';`,
		pg:     `ALTER TABLE sessions ADD COLUMN IF NOT EXISTS reason TEXT NOT NULL DEFAULT '';`,
	},
	{
		name: "023_access_requests",
		sqlite: `CREATE TABLE IF NOT EXISTS access_requests (
			id         TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL,
			username   TEXT NOT NULL,
			host_id    TEXT NOT NULL,
			reason     TEXT NOT NULL DEFAULT '',
			status     TEXT NOT NULL DEFAULT 'pending',
			decided_by TEXT NOT NULL DEFAULT '',
			decided_at TEXT,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		pg: `CREATE TABLE IF NOT EXISTS access_requests (
			id         TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL,
			username   TEXT NOT NULL,
			host_id    TEXT NOT NULL,
			reason     TEXT NOT NULL DEFAULT '',
			status     TEXT NOT NULL DEFAULT 'pending',
			decided_by TEXT NOT NULL DEFAULT '',
			decided_at TEXT,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
	},
	{
		name: "024_access_windows",
		sqlite: `CREATE TABLE IF NOT EXISTS access_windows (
			id          TEXT PRIMARY KEY,
			entity_type TEXT NOT NULL,
			entity_id   TEXT NOT NULL,
			days        TEXT NOT NULL DEFAULT '1-5',
			start_time  TEXT NOT NULL DEFAULT '09:00',
			end_time    TEXT NOT NULL DEFAULT '17:00',
			timezone    TEXT NOT NULL DEFAULT 'UTC'
		);`,
		pg: `CREATE TABLE IF NOT EXISTS access_windows (
			id          TEXT PRIMARY KEY,
			entity_type TEXT NOT NULL,
			entity_id   TEXT NOT NULL,
			days        TEXT NOT NULL DEFAULT '1-5',
			start_time  TEXT NOT NULL DEFAULT '09:00',
			end_time    TEXT NOT NULL DEFAULT '17:00',
			timezone    TEXT NOT NULL DEFAULT 'UTC'
		);`,
	},
	{
		name:   "025_hosts_require_reason",
		sqlite: `ALTER TABLE hosts ADD COLUMN require_reason INTEGER NOT NULL DEFAULT 0;`,
		pg:     `ALTER TABLE hosts ADD COLUMN IF NOT EXISTS require_reason INTEGER NOT NULL DEFAULT 0;`,
	},
	{
		name:   "026_hosts_requires_approval",
		sqlite: `ALTER TABLE hosts ADD COLUMN requires_approval INTEGER NOT NULL DEFAULT 0;`,
		pg:     `ALTER TABLE hosts ADD COLUMN IF NOT EXISTS requires_approval INTEGER NOT NULL DEFAULT 0;`,
	},
	{
		name:   "027_audit_log_instance_id",
		sqlite: `ALTER TABLE audit_log ADD COLUMN instance_id TEXT NOT NULL DEFAULT '';`,
		pg:     `ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS instance_id TEXT NOT NULL DEFAULT '';`,
	},
	{
		name:   "028_sessions_instance_id",
		sqlite: `ALTER TABLE sessions ADD COLUMN instance_id TEXT NOT NULL DEFAULT '';`,
		pg:     `ALTER TABLE sessions ADD COLUMN IF NOT EXISTS instance_id TEXT NOT NULL DEFAULT '';`,
	},
	{
		name:   "029_users_mfa_secret",
		sqlite: `ALTER TABLE users ADD COLUMN mfa_secret TEXT NOT NULL DEFAULT '';`,
		pg:     `ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret TEXT NOT NULL DEFAULT '';`,
	},
	{
		name:   "030_users_mfa_enabled",
		sqlite: `ALTER TABLE users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0;`,
		pg:     `ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled INTEGER NOT NULL DEFAULT 0;`,
	},
	{
		name:   "031_users_mfa_recovery_codes",
		sqlite: `ALTER TABLE users ADD COLUMN mfa_recovery_codes TEXT NOT NULL DEFAULT '';`,
		pg:     `ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_recovery_codes TEXT NOT NULL DEFAULT '';`,
	},
	{
		name: "032_create_password_history",
		sqlite: `CREATE TABLE IF NOT EXISTS password_history (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id     TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		pg: `CREATE TABLE IF NOT EXISTS password_history (
			id          SERIAL PRIMARY KEY,
			user_id     TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
	},
	{
		name:   "033_users_password_changed_at",
		sqlite: `ALTER TABLE users ADD COLUMN password_changed_at TEXT NOT NULL DEFAULT '';`,
		pg:     `ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TEXT NOT NULL DEFAULT '';`,
	},
	{
		name: "035_create_ip_rules",
		sqlite: `CREATE TABLE IF NOT EXISTS ip_rules (
			id          TEXT PRIMARY KEY,
			rule_type   TEXT NOT NULL DEFAULT 'deny',
			cidr        TEXT NOT NULL,
			scope       TEXT NOT NULL DEFAULT 'global',
			scope_id    TEXT NOT NULL DEFAULT '',
			description TEXT NOT NULL DEFAULT '',
			created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			created_by  TEXT NOT NULL DEFAULT ''
		);`,
		pg: `CREATE TABLE IF NOT EXISTS ip_rules (
			id          TEXT PRIMARY KEY,
			rule_type   TEXT NOT NULL DEFAULT 'deny',
			cidr        TEXT NOT NULL,
			scope       TEXT NOT NULL DEFAULT 'global',
			scope_id    TEXT NOT NULL DEFAULT '',
			description TEXT NOT NULL DEFAULT '',
			created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			created_by  TEXT NOT NULL DEFAULT ''
		);`,
	},
	{
		name:   "036_groups_max_sessions",
		sqlite: `ALTER TABLE groups ADD COLUMN max_sessions INTEGER NOT NULL DEFAULT 0;`,
		pg:     `ALTER TABLE groups ADD COLUMN IF NOT EXISTS max_sessions INTEGER NOT NULL DEFAULT 0;`,
	},
	{
		name: "034_create_mfa_pending",
		sqlite: `CREATE TABLE IF NOT EXISTS mfa_pending (
			token_hash  TEXT PRIMARY KEY,
			user_id     TEXT NOT NULL,
			ip          TEXT NOT NULL DEFAULT '',
			user_agent  TEXT NOT NULL DEFAULT '',
			created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at  TEXT NOT NULL
		);`,
		pg: `CREATE TABLE IF NOT EXISTS mfa_pending (
			token_hash  TEXT PRIMARY KEY,
			user_id     TEXT NOT NULL,
			ip          TEXT NOT NULL DEFAULT '',
			user_agent  TEXT NOT NULL DEFAULT '',
			created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at  TEXT NOT NULL
		);`,
	},
}

func Migrate(database *DB) error {
	_, err := database.DB.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		name       TEXT PRIMARY KEY,
		applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		return fmt.Errorf("create migrations table: %w", err)
	}

	for _, m := range migrations {
		if m.name == "006_create_schema_migrations" {
			continue
		}

		var count int
		err := database.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE name = ?", m.name).Scan(&count)
		if err != nil {
			return fmt.Errorf("check migration %s: %w", m.name, err)
		}
		if count > 0 {
			continue
		}

		ddl := m.sqlite
		if database.Driver == "postgres" && m.pg != "" {
			ddl = m.pg
		}

		// DDL has no placeholders so we bypass Rebind and use raw conn
		if _, err := database.DB.Exec(ddl); err != nil {
			return fmt.Errorf("apply migration %s: %w", m.name, err)
		}

		if _, err := database.Exec("INSERT INTO schema_migrations (name) VALUES (?)", m.name); err != nil {
			return fmt.Errorf("record migration %s: %w", m.name, err)
		}

		slog.Info("applied migration", "name", m.name)
	}

	return nil
}
