package api

import (
	"net/http"
	"time"

	"github.com/judsenb/gatekeeper/internal/db"
	"github.com/judsenb/gatekeeper/internal/instance"
	tlsgen "github.com/judsenb/gatekeeper/internal/tls"
)

type HealthHandler struct {
	DB             *db.DB
	DeploymentMode string
	TLS            *tlsgen.CertReloader
}

// 200 if process is alive. No dependency checks.
func (h *HealthHandler) Liveness(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, http.StatusOK, map[string]any{
		"status":          "ok",
		"instance_id":     instance.ID(),
		"deployment_mode": h.DeploymentMode,
	})
}

// 200 if DB reachable and cert valid, 503 otherwise.
func (h *HealthHandler) Readiness(w http.ResponseWriter, r *http.Request) {
	if h.DB == nil {
		jsonResponse(w, http.StatusServiceUnavailable, map[string]any{
			"status":          "no database",
			"instance_id":     instance.ID(),
			"deployment_mode": h.DeploymentMode,
		})
		return
	}
	if err := h.DB.Ping(); err != nil {
		jsonResponse(w, http.StatusServiceUnavailable, map[string]any{
			"status":          "database unreachable",
			"instance_id":     instance.ID(),
			"deployment_mode": h.DeploymentMode,
		})
		return
	}

	resp := map[string]any{
		"status":          "ready",
		"instance_id":     instance.ID(),
		"deployment_mode": h.DeploymentMode,
	}

	if h.TLS != nil {
		expiry := h.TLS.CertExpiry()
		resp["tls_cert_serial"] = h.TLS.CertSerial()
		resp["tls_cert_expires"] = expiry.Format(time.RFC3339)
		if !expiry.IsZero() && time.Now().After(expiry) {
			resp["status"] = "tls_cert_expired"
			jsonResponse(w, http.StatusServiceUnavailable, resp)
			return
		}
	}

	jsonResponse(w, http.StatusOK, resp)
}
