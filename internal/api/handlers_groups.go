package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/judsenb/gatekeeper/internal/models"
)

func (s *Stores) ListGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.Groups.List()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to list groups")
		return
	}
	if groups == nil {
		groups = []models.Group{}
	}
	jsonResponse(w, http.StatusOK, groups)
}

func (s *Stores) CreateGroup(w http.ResponseWriter, r *http.Request) {
	var g models.Group
	if err := decodeJSON(r, &g); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if g.Name == "" {
		jsonError(w, http.StatusBadRequest, "group name is required")
		return
	}
	if err := s.Groups.Create(&g); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create group")
		return
	}
	caller := UserFromContext(r.Context())
	if caller != nil {
		s.Audit.Log(&models.AuditEntry{
			Action:   "group_created",
			UserID:   caller.ID,
			Username: caller.Username,
			TargetID: g.ID,
			Target:   g.Name,
			SourceIP: r.RemoteAddr,
		})
	}
	jsonResponse(w, http.StatusCreated, g)
}

func (s *Stores) UpdateGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var g models.Group
	if err := decodeJSON(r, &g); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	g.ID = id
	if err := s.Groups.Update(&g); err != nil {
		jsonError(w, http.StatusNotFound, err.Error())
		return
	}
	caller := UserFromContext(r.Context())
	if caller != nil {
		s.Audit.Log(&models.AuditEntry{
			Action:   "group_updated",
			UserID:   caller.ID,
			Username: caller.Username,
			TargetID: g.ID,
			Target:   g.Name,
			SourceIP: r.RemoteAddr,
		})
	}
	jsonResponse(w, http.StatusOK, g)
}

func (s *Stores) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.Groups.Delete(id); err != nil {
		jsonError(w, http.StatusNotFound, err.Error())
		return
	}
	caller := UserFromContext(r.Context())
	if caller != nil {
		s.Audit.Log(&models.AuditEntry{
			Action:   "group_deleted",
			UserID:   caller.ID,
			Username: caller.Username,
			TargetID: id,
			SourceIP: r.RemoteAddr,
		})
	}
	w.WriteHeader(http.StatusNoContent)
}

// Returns IdP-to-GateKeeper group mappings (used by OIDC/SAML/LDAP).
func (s *Stores) ListGroupMappings(w http.ResponseWriter, r *http.Request) {
	mappings, err := s.GroupMappings.List()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to list group mappings")
		return
	}
	if mappings == nil {
		mappings = []models.GroupMapping{}
	}
	jsonResponse(w, http.StatusOK, mappings)
}

func (s *Stores) CreateGroupMapping(w http.ResponseWriter, r *http.Request) {
	var m models.GroupMapping
	if err := decodeJSON(r, &m); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if m.ExternalGroup == "" || m.GatekeeperGroup == "" {
		jsonError(w, http.StatusBadRequest, "external_group and gatekeeper_group are required")
		return
	}
	if err := s.GroupMappings.Create(&m); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create group mapping")
		return
	}
	caller := UserFromContext(r.Context())
	if caller != nil {
		s.Audit.Log(&models.AuditEntry{
			Action:   "group_mapping_created",
			UserID:   caller.ID,
			Username: caller.Username,
			TargetID: m.ID,
			Target:   m.ExternalGroup + " -> " + m.GatekeeperGroup,
			SourceIP: r.RemoteAddr,
		})
	}
	jsonResponse(w, http.StatusCreated, m)
}

func (s *Stores) DeleteGroupMapping(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.GroupMappings.Delete(id); err != nil {
		jsonError(w, http.StatusNotFound, err.Error())
		return
	}
	caller := UserFromContext(r.Context())
	if caller != nil {
		s.Audit.Log(&models.AuditEntry{
			Action:   "group_mapping_deleted",
			UserID:   caller.ID,
			Username: caller.Username,
			TargetID: id,
			SourceIP: r.RemoteAddr,
		})
	}
	w.WriteHeader(http.StatusNoContent)
}
