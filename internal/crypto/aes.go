package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/judsenb/gatekeeper/internal/secrets"
)

const (
	// yes this really needs to be 32 bytes exactly
	KeySize = 32
	// prefix so we know if a DB value is ciphertext or legacy plaintext
	EncryptedPrefix = "enc:v1:"
)

// KeyProvider resolves the encryption key: secrets backend → env → disabled.
type KeyProvider struct {
	key []byte
}

// NewKeyProvider tries secrets backend, then env, then gives up.
func NewKeyProvider(secretsBackend secrets.Backend) *KeyProvider {
	kp := &KeyProvider{}

	if secretsBackend != nil {
		if raw, err := secretsBackend.GetSecret("encryption_key"); err == nil && raw != "" {
			if k, err := decodeKey(raw); err == nil {
				kp.key = k
				return kp
			}
		}
	}

	if raw := os.Getenv("GK_ENCRYPTION_KEY"); raw != "" {
		if k, err := decodeKey(raw); err == nil {
			kp.key = k
			return kp
		}
	}

	return kp
}

func NewKeyProviderFromRaw(raw string) *KeyProvider {
	kp := &KeyProvider{}
	if k, err := decodeKey(raw); err == nil {
		kp.key = k
	}
	return kp
}

func (kp *KeyProvider) Enabled() bool {
	return len(kp.key) == KeySize
}

func (kp *KeyProvider) Key() []byte {
	return kp.key
}

// Encrypt produces EncryptedPrefix + base64(nonce||ciphertext||tag).
func Encrypt(key, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}
	ct := gcm.Seal(nonce, nonce, plaintext, nil)
	return EncryptedPrefix + base64.StdEncoding.EncodeToString(ct), nil
}

// Decrypt reverses Encrypt. No prefix = plaintext passthrough for old data.
func Decrypt(key []byte, value string) (string, error) {
	if !strings.HasPrefix(value, EncryptedPrefix) {
		return value, nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, EncryptedPrefix))
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(raw) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	plaintext, err := gcm.Open(nil, raw[:nonceSize], raw[nonceSize:], nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}
	return string(plaintext), nil
}

func EncryptBytes(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func DecryptBytes(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	return gcm.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], nil)
}

// decodeKey tries base64, hex, or raw 32-byte string. good luck.
func decodeKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)

	if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil && len(decoded) == KeySize {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(raw); err == nil && len(decoded) == KeySize {
		return decoded, nil
	}

	if len(raw) == KeySize*2 {
		decoded := make([]byte, KeySize)
		for i := 0; i < KeySize; i++ {
			_, err := fmt.Sscanf(raw[i*2:i*2+2], "%02x", &decoded[i])
			if err != nil {
				return nil, fmt.Errorf("hex decode: %w", err)
			}
		}
		return decoded, nil
	}

	if len(raw) == KeySize {
		return []byte(raw), nil
	}

	return nil, fmt.Errorf("encryption key must be 32 bytes (got %d)", len(raw))
}
