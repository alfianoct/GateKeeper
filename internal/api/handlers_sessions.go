package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/judsenb/gatekeeper/internal/models"
	"github.com/judsenb/gatekeeper/internal/recorder"
)

// Non-admins only see their own sessions.
func (s *Stores) ListActiveSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := s.Sessions.ListActive()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to list sessions")
		return
	}

	user := UserFromContext(r.Context())
	if user != nil && user.Role != "platform-admin" {
		var filtered []models.Session
		for _, sess := range sessions {
			if sess.UserID == user.ID {
				filtered = append(filtered, sess)
			}
		}
		sessions = filtered
	}

	if sessions == nil {
		sessions = []models.Session{}
	}
	jsonResponse(w, http.StatusOK, sessions)
}

// Non-admins only see their own sessions.
func (s *Stores) ListSessionHistory(w http.ResponseWriter, r *http.Request) {
	sessions, err := s.Sessions.ListHistory(50)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to list session history")
		return
	}

	user := UserFromContext(r.Context())
	if user != nil && user.Role != "platform-admin" {
		var filtered []models.Session
		for _, sess := range sessions {
			if sess.UserID == user.ID {
				filtered = append(filtered, sess)
			}
		}
		sessions = filtered
	}

	if sessions == nil {
		sessions = []models.Session{}
	}
	jsonResponse(w, http.StatusOK, sessions)
}

func (s *Stores) KillSession(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if s.SSHManager != nil {
		s.SSHManager.Kill(id)
	}

	if err := s.Sessions.Close(id); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to kill session")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Serves the asciicast recording. Path-traversal protected and ownership-checked.
func (s *Stores) GetSessionRecording(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	sess, err := s.Sessions.GetByID(id)
	if err != nil {
		jsonError(w, http.StatusNotFound, "session not found")
		return
	}

	recording := sess.Recording
	if recording == "" {
		jsonError(w, http.StatusNotFound, "no recording found for this session")
		return
	}

	// owner or admin only
	user := UserFromContext(r.Context())
	if user != nil && user.Role != "platform-admin" && user.ID != sess.UserID {
		jsonError(w, http.StatusForbidden, "access denied")
		return
	}

	// path traversal protection — recording must be inside recordings dir
	recDir := "./recordings"
	if s.Config != nil && s.Config.Audit.RecordingPath != "" {
		recDir = s.Config.Audit.RecordingPath
	}
	absRec, err := filepath.Abs(recording)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "invalid recording path")
		return
	}
	absDir, err := filepath.Abs(recDir)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "invalid recordings directory")
		return
	}
	if !strings.HasPrefix(absRec, absDir+string(os.PathSeparator)) {
		jsonError(w, http.StatusForbidden, "invalid recording path")
		return
	}

	if _, err := os.Stat(recording); os.IsNotExist(err) {
		jsonError(w, http.StatusNotFound, "recording file not found")
		return
	}

	data, err := recorder.ReadRecording(recording, s.Config.EncryptionKey)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to read recording: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "inline; filename=\""+filepath.Base(recording)+"\"")
	w.Write(data)
}
