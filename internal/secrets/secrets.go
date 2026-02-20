package secrets

import (
	"log/slog"
	"os"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/judsenb/gatekeeper/internal/config"
)

// Backend fetches secrets. callers fall back to DB/config if this returns empty.
type Backend interface {
	GetSecret(key string) (string, error)
}

const (
	KeyOIDCClientSecret = "oidc_client_secret"
	KeyLDAPBindPassword = "ldap_bind_password"
	KeyHostPassword     = "host_password" // prefix: host_password_<hostID>
)

func NewFromConfig(cfg config.SecretsConfig) Backend {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "env":
		return NewEnvBackend()
	case "vault":
		return NewVaultBackend(cfg.VaultAddr, cfg.VaultMount, cfg.VaultRole)
	default:
		return nil
	}
}

// NewEnvBackend maps key names to GK_SECRET_<UPPER> env vars.
func NewEnvBackend() Backend {
	return &envBackend{}
}

type envBackend struct{}

func (e *envBackend) GetSecret(key string) (string, error) {
	envKey := "GK_SECRET_" + strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
	v := os.Getenv(envKey)
	return strings.TrimSpace(v), nil
}

// NewVaultBackend uses VAULT_TOKEN for auth. k8s auth via role is a TODO.
func NewVaultBackend(addr, mount, role string) Backend {
	if addr == "" {
		return nil
	}
	if mount == "" {
		mount = "secret"
	}
	cfg := vaultapi.DefaultConfig()
	cfg.Address = addr
	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		slog.Warn("Vault client creation failed", "err", err)
		return &vaultBackend{addr: addr, mount: mount, role: role}
	}
	token := os.Getenv("VAULT_TOKEN")
	if token != "" {
		client.SetToken(token)
	} else if role != "" {
		slog.Warn("Vault role set but VAULT_TOKEN not set; Vault backend will return empty")
	}
	return &vaultBackend{addr: addr, mount: mount, role: role, client: client}
}

type vaultBackend struct {
	addr   string
	mount  string
	role   string
	client *vaultapi.Client
}

func (v *vaultBackend) GetSecret(key string) (string, error) {
	if v.client == nil || v.client.Token() == "" {
		return "", nil
	}
	// try KV v2 first (mount/data/key), fall back to v1 (mount/key)
	path := v.mount + "/data/" + strings.TrimPrefix(key, "/")
	secret, err := v.client.Logical().Read(path)
	if err != nil {
		slog.Debug("Vault read failed", "path", path, "err", err)
		return "", nil
	}
	if secret == nil || secret.Data == nil {
		pathV1 := v.mount + "/" + strings.TrimPrefix(key, "/")
		secret, err = v.client.Logical().Read(pathV1)
		if err != nil || secret == nil || secret.Data == nil {
			return "", nil
		}
		if val, ok := secret.Data[key].(string); ok {
			return val, nil
		}
		if val, ok := secret.Data["value"].(string); ok {
			return val, nil
		}
		return "", nil
	}
	if data, ok := secret.Data["data"].(map[string]interface{}); ok {
		if val, ok := data[key].(string); ok {
			return val, nil
		}
		if val, ok := data["value"].(string); ok {
			return val, nil
		}
	}
	if val, ok := secret.Data[key].(string); ok {
		return val, nil
	}
	if val, ok := secret.Data["value"].(string); ok {
		return val, nil
	}
	return "", nil
}

var _ Backend = (*envBackend)(nil)
var _ Backend = (*vaultBackend)(nil)
