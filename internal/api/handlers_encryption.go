package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/judsenb/gatekeeper/internal/crypto"
	"github.com/judsenb/gatekeeper/internal/models"
	"github.com/judsenb/gatekeeper/internal/recorder"
)

type EncryptionHandler struct {
	Settings     *models.SettingStore
	Sessions     *models.SessionStore
	Audit        *models.AuditStore
	RecordingDir string
	GetKey       func() []byte
}

func (h *EncryptionHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	key := h.GetKey()
	jsonResponse(w, http.StatusOK, map[string]any{
		"enabled": len(key) == crypto.KeySize,
	})
}

// Re-encrypts settings and recordings with a new key.
func (h *EncryptionHandler) RotateKey(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())

	var req struct {
		NewKey string `json:"new_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.NewKey == "" {
		jsonError(w, http.StatusBadRequest, "new_key is required (base64 or hex, 32 bytes)")
		return
	}

	oldKey := h.GetKey()

	newKP := crypto.NewKeyProviderFromRaw(req.NewKey)
	if !newKP.Enabled() {
		jsonError(w, http.StatusBadRequest, "invalid new_key: must decode to exactly 32 bytes")
		return
	}
	newKey := newKP.Key()

	var errs []string
	rotatedSettings := 0
	rotatedRecordings := 0

	for key := range models.SensitiveSettings {
		raw := h.Settings.Get(key, "")
		if raw == "" {
			continue
		}
		h.Settings.EncryptionKey = newKey
		if err := h.Settings.Set(key, raw); err != nil {
			errs = append(errs, fmt.Sprintf("setting %s: %v", key, err))
			continue
		}
		rotatedSettings++
	}
	h.Settings.EncryptionKey = newKey

	recDir := h.RecordingDir
	if recDir == "" {
		recDir = "./recordings"
	}
	entries, err := os.ReadDir(recDir)
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".cast") {
				continue
			}
			path := filepath.Join(recDir, entry.Name())
			if err := recorder.ReEncryptFile(path, oldKey, newKey); err != nil {
				errs = append(errs, fmt.Sprintf("recording %s: %v", entry.Name(), err))
				continue
			}
			rotatedRecordings++
		}
	}

	h.Audit.Log(&models.AuditEntry{
		Action:   "encryption_key_rotated",
		UserID:   user.ID,
		Username: user.Username,
		Detail:   fmt.Sprintf("settings=%d recordings=%d errors=%d", rotatedSettings, rotatedRecordings, len(errs)),
		SourceIP: r.RemoteAddr,
	})

	slog.Info("encryption key rotated",
		"settings", rotatedSettings,
		"recordings", rotatedRecordings,
		"errors", len(errs),
	)

	status := http.StatusOK
	if len(errs) > 0 {
		status = http.StatusPartialContent
	}
	jsonResponse(w, status, map[string]any{
		"rotated_settings":   rotatedSettings,
		"rotated_recordings": rotatedRecordings,
		"errors":             errs,
	})
}

// Encrypts existing unencrypted recordings. Useful when enabling encryption for the first time.
func (h *EncryptionHandler) EncryptExisting(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	key := h.GetKey()
	if len(key) != crypto.KeySize {
		jsonError(w, http.StatusBadRequest, "encryption is not enabled (no key configured)")
		return
	}

	recDir := h.RecordingDir
	if recDir == "" {
		recDir = "./recordings"
	}

	encrypted := 0
	var errs []string
	entries, err := os.ReadDir(recDir)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to read recordings directory")
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".cast") {
			continue
		}
		path := filepath.Join(recDir, entry.Name())
		if err := recorder.EncryptExistingFile(path, key); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", entry.Name(), err))
			continue
		}
		encrypted++
	}

	h.Audit.Log(&models.AuditEntry{
		Action:   "recordings_encrypted",
		UserID:   user.ID,
		Username: user.Username,
		Detail:   fmt.Sprintf("encrypted=%d errors=%d", encrypted, len(errs)),
		SourceIP: r.RemoteAddr,
	})

	jsonResponse(w, http.StatusOK, map[string]any{
		"encrypted": encrypted,
		"errors":    errs,
	})
}
