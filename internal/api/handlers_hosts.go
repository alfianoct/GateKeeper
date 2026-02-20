package api

import (
	"database/sql"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/judsenb/gatekeeper/internal/models"
)

// Non-admins only see hosts their groups grant access to.
func (s *Stores) ListHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.Hosts.List()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to list hosts")
		return
	}

	user := UserFromContext(r.Context())
	if user != nil && user.Role != "platform-admin" {
		var userGroups []string
		if user.Groups != "" {
			for _, g := range strings.Split(user.Groups, ",") {
				userGroups = append(userGroups, strings.TrimSpace(g))
			}
		}
		var filtered []models.Host
		for _, h := range hosts {
			allowed, err := s.Groups.CheckAccess(userGroups, h.ID)
			if err != nil {
				slog.Warn("CheckAccess failed, denying host", "host_id", h.ID, "err", err)
				continue
			}
			if allowed {
				filtered = append(filtered, h)
			}
		}
		hosts = filtered
	}

	if hosts == nil {
		hosts = []models.Host{}
	}
	// never expose SSH passwords; tag hosts that are currently in use
	active, err := s.Sessions.ListActive()
	if err != nil {
		slog.Warn("ListActive sessions failed", "err", err)
		active = nil
	}
	inUseBy := make(map[string]string)
	for _, sess := range active {
		if sess.HostID != "" && inUseBy[sess.HostID] == "" {
			inUseBy[sess.HostID] = sess.Username
		}
	}
	for i := range hosts {
		hosts[i].SSHPassword = ""
		hosts[i].InUseBy = inUseBy[hosts[i].ID]
	}
	jsonResponse(w, http.StatusOK, hosts)
}

// RBAC-gated — non-admins can only see hosts they have access to.
func (s *Stores) GetHost(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	host, err := s.Hosts.GetByID(id)
	if err == sql.ErrNoRows {
		jsonError(w, http.StatusNotFound, "host not found")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to get host")
		return
	}

	user := UserFromContext(r.Context())
	if user != nil && user.Role != "platform-admin" {
		var userGroups []string
		if user.Groups != "" {
			for _, g := range strings.Split(user.Groups, ",") {
				userGroups = append(userGroups, strings.TrimSpace(g))
			}
		}
		allowed, checkErr := s.Groups.CheckAccess(userGroups, host.ID)
		if checkErr != nil {
			slog.Warn("CheckAccess failed", "host_id", host.ID, "err", checkErr)
			jsonError(w, http.StatusNotFound, "host not found")
			return
		}
		if !allowed {
			jsonError(w, http.StatusNotFound, "host not found")
			return
		}
	}

	host.SSHPassword = ""
	jsonResponse(w, http.StatusOK, host)
}

// Same RBAC as GetHost.
func (s *Stores) GetHostActiveSession(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	host, err := s.Hosts.GetByID(id)
	if err == sql.ErrNoRows {
		jsonError(w, http.StatusNotFound, "host not found")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to get host")
		return
	}
	user := UserFromContext(r.Context())
	if user != nil && user.Role != "platform-admin" {
		var userGroups []string
		if user.Groups != "" {
			for _, g := range strings.Split(user.Groups, ",") {
				userGroups = append(userGroups, strings.TrimSpace(g))
			}
		}
		allowed, err := s.Groups.CheckAccess(userGroups, host.ID)
		if err != nil {
			slog.Warn("CheckAccess failed", "host_id", host.ID, "err", err)
			jsonError(w, http.StatusNotFound, "host not found")
			return
		}
		if !allowed {
			jsonError(w, http.StatusNotFound, "host not found")
			return
		}
	}
	sess, err := s.Sessions.GetActiveByHostID(id)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to check active session")
		return
	}
	if sess == nil {
		jsonResponse(w, http.StatusOK, map[string]interface{}{"in_use": false})
		return
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"in_use":   true,
		"username": sess.Username,
	})
}

func (s *Stores) CreateHost(w http.ResponseWriter, r *http.Request) {
	var h models.Host
	if err := decodeJSON(r, &h); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if h.Name == "" || h.Hostname == "" {
		jsonError(w, http.StatusBadRequest, "name and hostname are required")
		return
	}
	if err := s.Hosts.Create(&h); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create host")
		return
	}
	caller := UserFromContext(r.Context())
	if caller != nil {
		s.Audit.Log(&models.AuditEntry{
			Action:   "host_created",
			UserID:   caller.ID,
			Username: caller.Username,
			TargetID: h.ID,
			Target:   h.Name,
			SourceIP: r.RemoteAddr,
		})
	}
	jsonResponse(w, http.StatusCreated, h)
}

func (s *Stores) UpdateHost(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var h models.Host
	if err := decodeJSON(r, &h); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	h.ID = id
	if err := s.Hosts.Update(&h); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to update host")
		return
	}
	caller := UserFromContext(r.Context())
	if caller != nil {
		s.Audit.Log(&models.AuditEntry{
			Action:   "host_updated",
			UserID:   caller.ID,
			Username: caller.Username,
			TargetID: h.ID,
			Target:   h.Name,
			SourceIP: r.RemoteAddr,
		})
	}
	jsonResponse(w, http.StatusOK, h)
}

func (s *Stores) DeleteHost(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.Hosts.Delete(id); err != nil {
		jsonError(w, http.StatusNotFound, err.Error())
		return
	}
	caller := UserFromContext(r.Context())
	if caller != nil {
		s.Audit.Log(&models.AuditEntry{
			Action:   "host_deleted",
			UserID:   caller.ID,
			Username: caller.Username,
			TargetID: id,
			SourceIP: r.RemoteAddr,
		})
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Stores) ToggleHostDisabled(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	host, err := s.Hosts.GetByID(id)
	if err == sql.ErrNoRows {
		jsonError(w, http.StatusNotFound, "host not found")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to get host")
		return
	}
	newDisabled := !host.Disabled
	if err := s.Hosts.SetDisabled(id, newDisabled); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to toggle host")
		return
	}
	host.Disabled = newDisabled
	host.SSHPassword = ""
	caller := UserFromContext(r.Context())
	if caller != nil {
		action := "host_enabled"
		if newDisabled {
			action = "host_disabled"
		}
		s.Audit.Log(&models.AuditEntry{
			Action:   action,
			UserID:   caller.ID,
			Username: caller.Username,
			TargetID: host.ID,
			Target:   host.Name,
			SourceIP: r.RemoteAddr,
		})
	}
	jsonResponse(w, http.StatusOK, host)
}
