package api

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/judsenb/gatekeeper/internal/models"
)

func (s *Stores) CreateAccessRequest(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		jsonError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	var body struct {
		HostID string `json:"host_id"`
		Reason string `json:"reason"`
	}
	if err := decodeJSON(r, &body); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	body.HostID = strings.TrimSpace(body.HostID)
	if body.HostID == "" {
		jsonError(w, http.StatusBadRequest, "host_id required")
		return
	}
	// still need RBAC to the host even though it requires approval
	var userGroups []string
	if user.Groups != "" {
		for _, g := range strings.Split(user.Groups, ",") {
			userGroups = append(userGroups, strings.TrimSpace(g))
		}
	}
	allowed, err := s.Groups.CheckAccess(userGroups, body.HostID)
	if err != nil || !allowed {
		jsonError(w, http.StatusForbidden, "access denied to this host")
		return
	}
	req := &models.AccessRequest{
		UserID:   user.ID,
		Username: user.Username,
		HostID:   body.HostID,
		Reason:   strings.TrimSpace(body.Reason),
	}
	if err := s.AccessRequests.Create(req); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create request")
		return
	}
	jsonResponse(w, http.StatusCreated, req)
}

func (s *Stores) ListAccessRequests(w http.ResponseWriter, r *http.Request) {
	list, err := s.AccessRequests.ListPending(50)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to list requests")
		return
	}
	jsonResponse(w, http.StatusOK, list)
}

func (s *Stores) ApproveAccessRequest(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		jsonError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	id := chi.URLParam(r, "id")
	if err := s.AccessRequests.Approve(id, user.Username); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to approve")
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"status": "approved"})
}

func (s *Stores) RejectAccessRequest(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		jsonError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	id := chi.URLParam(r, "id")
	if err := s.AccessRequests.Reject(id, user.Username); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to reject")
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"status": "rejected"})
}

func (s *Stores) ListAccessWindows(w http.ResponseWriter, r *http.Request) {
	entityType := r.URL.Query().Get("entity_type")
	entityID := r.URL.Query().Get("entity_id")
	list, err := s.AccessWindows.List(entityType, entityID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to list access windows")
		return
	}
	jsonResponse(w, http.StatusOK, list)
}

func (s *Stores) CreateAccessWindow(w http.ResponseWriter, r *http.Request) {
	var aw models.AccessWindow
	if err := decodeJSON(r, &aw); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	aw.EntityType = strings.TrimSpace(aw.EntityType)
	aw.EntityID = strings.TrimSpace(aw.EntityID)
	if aw.EntityType != "host" && aw.EntityType != "group" {
		jsonError(w, http.StatusBadRequest, "entity_type must be host or group")
		return
	}
	if aw.EntityID == "" {
		jsonError(w, http.StatusBadRequest, "entity_id required")
		return
	}
	if aw.Days == "" {
		aw.Days = "1-5"
	}
	if aw.StartTime == "" {
		aw.StartTime = "09:00"
	}
	if aw.EndTime == "" {
		aw.EndTime = "17:00"
	}
	if aw.Timezone == "" {
		aw.Timezone = "UTC"
	}
	if err := s.AccessWindows.Create(&aw); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create access window")
		return
	}
	jsonResponse(w, http.StatusCreated, aw)
}

func (s *Stores) DeleteAccessWindow(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.AccessWindows.Delete(id); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to delete")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
