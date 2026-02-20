package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/judsenb/gatekeeper/internal/models"
)

func (s *Stores) ListKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.Keys.List()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to list keys")
		return
	}
	if keys == nil {
		keys = []models.SSHKey{}
	}
	jsonResponse(w, http.StatusOK, keys)
}

func (s *Stores) CreateKey(w http.ResponseWriter, r *http.Request) {
	var k models.SSHKey
	if err := decodeJSON(r, &k); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if k.Name == "" || k.PublicKey == "" {
		jsonError(w, http.StatusBadRequest, "name and public_key are required")
		return
	}
	if err := s.Keys.Create(&k); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create key")
		return
	}
	caller := UserFromContext(r.Context())
	if caller != nil {
		s.Audit.Log(&models.AuditEntry{
			Action:   "key_created",
			UserID:   caller.ID,
			Username: caller.Username,
			TargetID: k.ID,
			Target:   k.Name,
			SourceIP: r.RemoteAddr,
		})
	}
	k.PrivateKey = ""
	jsonResponse(w, http.StatusCreated, k)
}

func (s *Stores) DeleteKey(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.Keys.Delete(id); err != nil {
		jsonError(w, http.StatusNotFound, err.Error())
		return
	}
	caller := UserFromContext(r.Context())
	if caller != nil {
		s.Audit.Log(&models.AuditEntry{
			Action:   "key_deleted",
			UserID:   caller.ID,
			Username: caller.Username,
			TargetID: id,
			SourceIP: r.RemoteAddr,
		})
	}
	w.WriteHeader(http.StatusNoContent)
}
