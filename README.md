# GateKeeper

GateKeeper is a self-hosted SSH access gateway written in Go.

It acts as a centralized control layer in front of SSH, providing access
control, MFA enforcement, session recording, auditing, and policy
enforcement --- all delivered as a single binary with an embedded web
UI.

No external control plane. No SaaS dependency.

------------------------------------------------------------------------

## What It Is (and Isn't)

GateKeeper is not a traditional minimal "bastion host" in the classic
hardened jump-box sense.

Instead, it's an SSH access gateway designed to centralize
authentication, authorization, and auditing for SSH environments.

The goal is controlled access and visibility --- not a zero-service
hardened OS model.

------------------------------------------------------------------------

## Features

-   Browser-based SSH proxy (WebSocket + xterm.js)
-   Session recording (asciicast v2, optional AES-256-GCM encryption)
-   Local auth (bcrypt) + LDAP / OIDC / SAML
-   TOTP-based MFA (policy enforced)
-   RBAC with granular permissions
-   Approval workflows and time-based access windows
-   Audit logging with webhook (HMAC) and syslog export
-   IP allow/deny rules (CIDR, deny-first)
-   Concurrent session limits (global + per-group)
-   Secrets backend (Vault or environment variables)
-   TLS hot-reload
-   Prometheus metrics
-   /health and /ready endpoints
-   Instance identity tracking

------------------------------------------------------------------------

## Status

GateKeeper is functional and actively tested.

-   Single-instance deployments are stable
-   SQLite is the primary development database
-   Postgres support exists but needs broader real-world validation
-   HA / multi-instance mode is not production-ready

------------------------------------------------------------------------

## Quick Start

GateKeeper is built for Linux. Linux is the supported production
platform.

Docker is the recommended way to run GateKeeper for consistent and
secure deployments.

Windows and macOS builds may work for development, but production
deployments should use Linux.

### Build

``` bash
git clone https://github.com/judsenb/gatekeeper.git
cd gatekeeper
make build
./gatekeeper
```

On first run, open:

https://localhost:8443

------------------------------------------------------------------------

### Docker

``` bash
docker compose up -d
```

SQLite is the default. Configure Postgres via environment variables if
needed.

------------------------------------------------------------------------

## Configuration

GateKeeper uses a YAML config file with environment variable overrides.

Common environment variables:

-   GK_DB_DRIVER --- sqlite or postgres\
-   GK_DB_DSN --- Postgres connection string\
-   GK_TLS_CERT / GK_TLS_KEY --- TLS files\
-   GK_ENCRYPTION_KEY --- 32-byte key (hex or base64)\
-   GK_DEPLOYMENT_MODE --- single or ha\
-   GK_INSTANCE_ID --- override auto-generated instance ID

If TLS files are present, HTTP redirects to HTTPS. Certificates reload
automatically when updated.

------------------------------------------------------------------------

## Development

``` bash
make build
make test
make cover
make check
```

Tests use in-memory SQLite. CI runs linting, tests, and vulnerability
checks.

------------------------------------------------------------------------

## License

MIT
