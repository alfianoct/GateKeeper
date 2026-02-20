package api

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/judsenb/gatekeeper/internal/auth"
	"github.com/judsenb/gatekeeper/internal/models"
)

func (s *Stores) ListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.Users.List()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to list users")
		return
	}
	if users == nil {
		users = []models.User{}
	}
	jsonResponse(w, http.StatusOK, users)
}

func (s *Stores) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
		Role        string `json:"role"`
		Groups      string `json:"groups"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		jsonError(w, http.StatusBadRequest, "username and password required")
		return
	}

	policy := loadPasswordPolicy(s.Settings)
	if err := auth.ValidatePasswordPolicy(req.Password, policy); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.Role == "" {
		req.Role = "user"
	}

	if req.Role != "user" && req.Role != "platform-admin" {
		jsonError(w, http.StatusBadRequest, "role must be 'user' or 'platform-admin'")
		return
	}

	user := &models.User{
		Username:    req.Username,
		DisplayName: req.DisplayName,
		Role:        req.Role,
		Groups:      req.Groups,
	}

	if err := s.Users.Create(user, req.Password); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			jsonError(w, http.StatusConflict, "username already exists")
			return
		}
		jsonError(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	caller := UserFromContext(r.Context())
	if caller != nil {
		s.Audit.Log(&models.AuditEntry{
			Action:   "user_created",
			UserID:   caller.ID,
			Username: caller.Username,
			TargetID: user.ID,
			Target:   user.Username,
			SourceIP: r.RemoteAddr,
		})
	}

	jsonResponse(w, http.StatusCreated, user)
}

func (s *Stores) UpdateUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	existing, err := s.Users.GetByID(id)
	if err != nil {
		jsonError(w, http.StatusNotFound, "user not found")
		return
	}

	var req struct {
		DisplayName *string `json:"display_name"`
		Role        *string `json:"role"`
		Groups      *string `json:"groups"`
		Disabled    *bool   `json:"disabled"`
		Password    *string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if req.Password != nil && *req.Password != "" {
		policy := loadPasswordPolicy(s.Settings)
		if err := auth.ValidatePasswordPolicy(*req.Password, policy); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	if req.DisplayName != nil {
		existing.DisplayName = *req.DisplayName
	}
	if req.Role != nil {
		if *req.Role != "user" && *req.Role != "platform-admin" {
			jsonError(w, http.StatusBadRequest, "role must be 'user' or 'platform-admin'")
			return
		}
		existing.Role = *req.Role
	}
	if req.Groups != nil {
		existing.Groups = *req.Groups
	}
	if req.Disabled != nil {
		existing.Disabled = *req.Disabled
	}

	if err := s.Users.Update(existing); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to update user")
		return
	}

	if req.Password != nil && *req.Password != "" {
		if err := s.Users.SetPassword(id, *req.Password); err != nil {
			jsonError(w, http.StatusInternalServerError, "failed to update password")
			return
		}
	}

	jsonResponse(w, http.StatusOK, existing)
}

func (s *Stores) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	caller := UserFromContext(r.Context())
	if caller != nil && caller.ID == id {
		jsonError(w, http.StatusBadRequest, "cannot delete your own account")
		return
	}

	if err := s.Users.Delete(id); err != nil {
		jsonError(w, http.StatusNotFound, err.Error())
		return
	}

	// also nuke all their sessions so they can't linger
	if s.AuthSessions != nil {
		s.AuthSessions.DestroyAllForUser(id)
	}

	w.WriteHeader(http.StatusNoContent)
}
