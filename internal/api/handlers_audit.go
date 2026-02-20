package api

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/judsenb/gatekeeper/internal/models"
)

func (s *Stores) ListAuditLog(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit := 100
	offset := 0
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 500 {
		limit = l
	}
	const maxOffset = 10_000
	if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
		if o > maxOffset {
			offset = maxOffset
		} else {
			offset = o
		}
	}

	entries, err := s.Audit.List(action, limit, offset)
	if err != nil {
		slog.Warn("audit list failed", "action", action, "limit", limit, "offset", offset, "err", err)
		jsonError(w, http.StatusInternalServerError, "failed to list audit log")
		return
	}
	if entries == nil {
		entries = []models.AuditEntry{}
	}
	jsonResponse(w, http.StatusOK, entries)
}
