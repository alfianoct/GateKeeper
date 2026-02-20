package api

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/judsenb/gatekeeper/internal/audit"
	"github.com/judsenb/gatekeeper/internal/models"
)

// Reads settings and rebuilds the dispatcher's exporter list.
func ConfigureAuditExporters(d *audit.Dispatcher, settings *models.SettingStore) {
	var exporters []audit.Exporter

	webhookURL := strings.TrimSpace(settings.Get(models.SettingAuditWebhookURL, ""))
	if webhookURL != "" {
		secret := settings.Get(models.SettingAuditWebhookSecret, "")
		exporters = append(exporters, audit.NewWebhook(webhookURL, secret))
		slog.Info("audit export: webhook configured", "url", webhookURL)
	}

	syslogAddr := strings.TrimSpace(settings.Get(models.SettingAuditSyslogAddr, ""))
	if syslogAddr != "" {
		facility, _ := strconv.Atoi(settings.Get(models.SettingAuditSyslogFacility, "1"))
		exporters = append(exporters, audit.NewSyslog(syslogAddr, facility))
		slog.Info("audit export: syslog configured", "addr", syslogAddr)
	}

	d.SetExporters(exporters)
	if len(exporters) == 0 {
		slog.Debug("audit export: no exporters configured")
	}
}

type AuditExportHandler struct {
	Audit    *models.AuditStore
	Settings *models.SettingStore
}

// Sends a test event to the configured webhook.
func (h *AuditExportHandler) TestWebhook(w http.ResponseWriter, r *http.Request) {
	url := strings.TrimSpace(h.Settings.Get(models.SettingAuditWebhookURL, ""))
	if url == "" {
		jsonError(w, http.StatusBadRequest, "no webhook URL configured — save one in Settings first")
		return
	}
	secret := h.Settings.Get(models.SettingAuditWebhookSecret, "")

	if err := audit.TestWebhook(url, secret); err != nil {
		jsonError(w, http.StatusBadGateway, fmt.Sprintf("webhook test failed: %v", err))
		return
	}

	caller := UserFromContext(r.Context())
	if caller != nil {
		h.Audit.Log(&models.AuditEntry{
			Action:   "audit_webhook_test",
			UserID:   caller.ID,
			Username: caller.Username,
			SourceIP: r.RemoteAddr,
		})
	}

	jsonResponse(w, http.StatusOK, map[string]any{"ok": true, "message": "webhook test event sent successfully"})
}

// Exports audit log as JSON or CSV with date range filtering.
func (h *AuditExportHandler) BulkExport(w http.ResponseWriter, r *http.Request) {
	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "csv" {
		jsonError(w, http.StatusBadRequest, "format must be 'json' or 'csv'")
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 10000
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 50000 {
		limit = l
	}

	entries, err := h.Audit.ListRange(fromStr, toStr, limit)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to query audit log")
		return
	}

	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=gatekeeper-audit-%s.csv", time.Now().UTC().Format("20060102-150405")))
		cw := csv.NewWriter(w)
		cw.Write([]string{"timestamp", "action", "user_id", "username", "target_id", "target", "detail", "source_ip", "session_id", "reason"})
		for _, e := range entries {
			cw.Write([]string{e.Timestamp, e.Action, e.UserID, e.Username, e.TargetID, e.Target, e.Detail, e.SourceIP, e.SessionID, e.Reason})
		}
		cw.Flush()
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=gatekeeper-audit-%s.json", time.Now().UTC().Format("20060102-150405")))
	json.NewEncoder(w).Encode(entries)
}
