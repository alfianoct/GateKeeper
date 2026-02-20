package api

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
	"github.com/judsenb/gatekeeper/internal/config"
	"github.com/judsenb/gatekeeper/internal/id"
	"github.com/judsenb/gatekeeper/internal/metrics"
	"github.com/judsenb/gatekeeper/internal/models"
	"github.com/judsenb/gatekeeper/internal/recorder"
	sshpkg "github.com/judsenb/gatekeeper/internal/ssh"
	"golang.org/x/crypto/ssh"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  8192,
	WriteBufferSize: 8192,
	// default origin check rejects cross-origin — don't change this
}

type wsMessage struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
}

type wsInputData struct {
	Data string `json:"data"`
}

type wsResizeData struct {
	Cols int `json:"cols"`
	Rows int `json:"rows"`
}

// Upgrades to WebSocket, dials target SSH host, bridges I/O.
type SSHWebSocketHandler struct {
	Hosts          *models.HostStore
	Sessions       *models.SessionStore
	Audit          *models.AuditStore
	Groups         *models.GroupStore
	Keys           *models.KeyStore
	HostKeys       *models.HostKeyStore
	SSHManager     *sshpkg.SessionManager
	Config         *config.Config
	AccessRequests *models.AccessRequestStore
	AccessWindows  *models.AccessWindowStore
	IPRules        *models.IPRuleStore
	Settings       *models.SettingStore
	EncryptionKey  []byte
}

// Trust-On-First-Use: stores key on first connect, rejects if it changes later.
func tofuHostKeyCallback(hostKeys *models.HostKeyStore, hostID string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		keyType := key.Type()
		stored, err := hostKeys.Get(hostID, keyType)
		if err != nil {
			if err == sql.ErrNoRows {
				pubKey := base64.StdEncoding.EncodeToString(key.Marshal())
				slog.Info("TOFU: storing host key", "hostname", hostname, "key_type", keyType)
				return hostKeys.Save(hostID, keyType, pubKey)
			}
			return fmt.Errorf("host key lookup: %w", err)
		}
		currentKey := base64.StdEncoding.EncodeToString(key.Marshal())
		if currentKey != stored {
			return fmt.Errorf("HOST KEY CHANGED for %s — possible MITM attack (key type %s)", hostname, keyType)
		}
		return nil
	}
}

func (h *SSHWebSocketHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hostID := chi.URLParam(r, "hostId")

	host, err := h.Hosts.GetByID(hostID)
	if err == sql.ErrNoRows {
		http.Error(w, "host not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "failed to look up host", http.StatusInternalServerError)
		return
	}
	if host.Disabled {
		http.Error(w, "host is disabled", http.StatusForbidden)
		return
	}

	user := UserFromContext(r.Context())
	username := "anonymous"
	userID := "unknown"
	var userGroups []string
	sourceIP := r.RemoteAddr
	if user != nil {
		username = user.Username
		userID = user.ID
		if user.Groups != "" {
			for _, g := range strings.Split(user.Groups, ",") {
				userGroups = append(userGroups, strings.TrimSpace(g))
			}
		}
	}

	// platform admins bypass RBAC
	isPlatformAdmin := user != nil && user.Role == "platform-admin"
	if !isPlatformAdmin {
		allowed, err := h.Groups.CheckAccess(userGroups, host.ID)
		if err != nil {
			slog.Warn("WS access check error", "err", err)
			http.Error(w, "access check failed", http.StatusInternalServerError)
			return
		}
		if !allowed {
			h.Audit.Log(&models.AuditEntry{
				Action:   "denied",
				UserID:   userID,
				Username: username,
				TargetID: host.ID,
				Target:   host.Name,
				Detail:   "access denied by RBAC policy",
				SourceIP: sourceIP,
			})
			http.Error(w, "access denied", http.StatusForbidden)
			return
		}
	}

	reason := strings.TrimSpace(r.URL.Query().Get("reason"))
	if host.RequireReason && reason == "" {
		h.Audit.Log(&models.AuditEntry{
			Action:   "denied",
			UserID:   userID,
			Username: username,
			TargetID: host.ID,
			Target:   host.Name,
			Detail:   "reason for access required but not provided",
			SourceIP: sourceIP,
		})
		http.Error(w, "Reason for access is required for this host", http.StatusBadRequest)
		return
	}

	if h.AccessWindows != nil {
		within, err := h.AccessWindows.WithinWindow(host.ID, userGroups, time.Now())
		if err != nil {
			slog.Warn("access window check error", "err", err)
			http.Error(w, "access check failed", http.StatusInternalServerError)
			return
		}
		if !within {
			h.Audit.Log(&models.AuditEntry{
				Action:   "denied",
				UserID:   userID,
				Username: username,
				TargetID: host.ID,
				Target:   host.Name,
				Detail:   "access outside allowed time window",
				SourceIP: sourceIP,
			})
			http.Error(w, "Access is not allowed outside the configured time window", http.StatusForbidden)
			return
		}
	}

	// must have an approved request within TTL
	if host.RequiresApproval && h.AccessRequests != nil {
		ok, err := h.AccessRequests.HasApprovedRequest(userID, host.ID, models.ApprovalTTL)
		if err != nil {
			slog.Warn("access request check error", "err", err)
			http.Error(w, "access check failed", http.StatusInternalServerError)
			return
		}
		if !ok {
			h.Audit.Log(&models.AuditEntry{
				Action:   "denied",
				UserID:   userID,
				Username: username,
				TargetID: host.ID,
				Target:   host.Name,
				Detail:   "host requires approval; no valid approved request",
				SourceIP: sourceIP,
			})
			http.Error(w, "This host requires approval. Submit an access request and wait for approval before connecting.", http.StatusForbidden)
			return
		}
	}

	if h.IPRules != nil {
		allowed, reason := h.IPRules.Check(sourceIP, "host", host.ID)
		if !allowed {
			h.Audit.Log(&models.AuditEntry{
				Action:   "ip_blocked",
				UserID:   userID,
				Username: username,
				TargetID: host.ID,
				Target:   host.Name,
				Detail:   reason,
				SourceIP: sourceIP,
			})
			http.Error(w, "Access denied by IP policy for this host", http.StatusForbidden)
			return
		}
	}

	// session limit: whichever is lower between global and group limit wins
	if h.Settings != nil && h.Sessions != nil && userID != "unknown" {
		globalLimit := atoi(h.Settings.Get(models.SettingMaxSessionsPerUser, "0"))
		groupLimit := h.Groups.MaxSessionsForUser(userGroups)
		effectiveLimit := globalLimit
		if groupLimit > 0 && (effectiveLimit == 0 || groupLimit < effectiveLimit) {
			effectiveLimit = groupLimit
		}
		if effectiveLimit > 0 {
			activeCount, err := h.Sessions.CountActiveByUserID(userID)
			if err != nil {
				slog.Warn("session count error", "err", err)
			} else if activeCount >= effectiveLimit {
				h.Audit.Log(&models.AuditEntry{
					Action:   "session_limit",
					UserID:   userID,
					Username: username,
					TargetID: host.ID,
					Target:   host.Name,
					Detail:   fmt.Sprintf("session limit reached (%d/%d active)", activeCount, effectiveLimit),
					SourceIP: sourceIP,
				})
				http.Error(w, fmt.Sprintf("Session limit reached (%d/%d active)", activeCount, effectiveLimit), http.StatusTooManyRequests)
				return
			}
		}
	}

	sshUser := host.SSHUser
	if sshUser == "" {
		sshUser = username
	}
	sshPassword := host.SSHPassword
	keyID := host.SSHKeyID

	timeout := h.Config.SSH.ConnectTimeoutDuration()

	port := host.Port
	if port == 0 {
		port = h.Config.SSH.DefaultPort
		if port == 0 {
			port = 22
		}
	}

	// one active session per host — admin can kick existing user
	existing, err := h.Sessions.GetActiveByHostID(host.ID)
	if err != nil {
		http.Error(w, "failed to check host lock", http.StatusInternalServerError)
		return
	}
	if existing != nil {
		if existing.UserID == userID {
			http.Error(w, "You already have an active session to this host. Close it before opening another.", http.StatusConflict)
			return
		}
		if isPlatformAdmin {
			h.SSHManager.Kill(existing.ID)
			if err := h.Sessions.Close(existing.ID); err != nil {
				slog.Warn("failed to close session on takeover", "session_id", existing.ID, "err", err)
			}
			h.SSHManager.Watchers.CloseSession(existing.ID)
			h.Audit.Log(&models.AuditEntry{
				Action:    "session_taken_over",
				UserID:    userID,
				Username:  username,
				TargetID:  host.ID,
				Target:    host.Name,
				Detail:    fmt.Sprintf("kicked session %s (was %s)", existing.ID, existing.Username),
				SourceIP:  sourceIP,
				SessionID: existing.ID,
			})
			slog.Info("admin took over host session", "host", host.Name, "kicked_session", existing.ID, "kicked_user", existing.Username, "admin", username)
		} else {
			http.Error(w, "Host is in use by another user. Try again when they disconnect.", http.StatusLocked)
			return
		}
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Warn("WS upgrade failed", "err", err)
		return
	}
	defer ws.Close()

	// 64 KB max incoming message — terminal input shouldn't be bigger than this
	ws.SetReadLimit(65536)

	var privateKey []byte
	if keyID != "" {
		storedKey, err := h.Keys.GetByID(keyID)
		if err == nil && storedKey.PrivateKey != "" {
			privateKey = []byte(storedKey.PrivateKey)
			h.Keys.TouchLastUsed(keyID)
		}
	} else if sshPassword == "" {
		// no password and no key on host — try user keys as a last resort
		userKeys, err := h.Keys.GetByUserID(userID)
		if err == nil {
			for _, k := range userKeys {
				if k.PrivateKey != "" {
					privateKey = []byte(k.PrivateKey)
					h.Keys.TouchLastUsed(k.ID)
					break
				}
			}
		}
	}

	sendWSOutput(ws, fmt.Sprintf("\x1b[32mConnecting to %s (%s:%d)...\x1b[0m\r\n", host.Name, host.Hostname, port))

	proxySession, err := sshpkg.Connect(sshpkg.ConnectConfig{
		Host:            host.Hostname,
		Port:            port,
		Username:        sshUser,
		Password:        sshPassword,
		PrivateKey:      privateKey,
		Timeout:         timeout,
		HostKeyCallback: tofuHostKeyCallback(h.HostKeys, host.ID),
	})
	if err != nil {
		errMsg := fmt.Sprintf("\x1b[31mConnection failed: %s\x1b[0m\r\n", err.Error())
		sendWSOutput(ws, errMsg)
		slog.Warn("WS SSH connect failed", "host", host.Name, "err", err)

		h.Audit.Log(&models.AuditEntry{
			Action:   "denied",
			UserID:   userID,
			Username: username,
			TargetID: host.ID,
			Target:   host.Name,
			Detail:   "SSH connection failed: " + err.Error(),
			SourceIP: sourceIP,
		})
		return
	}

	sessionID, err := id.Short()
	if err != nil {
		slog.Error("failed to generate session id", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	proxySession.ID = sessionID
	proxySession.HostID = host.ID
	proxySession.HostName = host.Name
	proxySession.Username = username
	proxySession.UserID = userID

	h.SSHManager.Register(proxySession)
	metrics.SSHConnects.Add(1)
	metrics.SessionsActive.Add(1)

	var rec *recorder.Recorder
	if h.Config.Audit.RecordSessions {
		recDir := h.Config.Audit.RecordingPath
		if recDir == "" {
			recDir = "./recordings"
		}
		title := fmt.Sprintf("%s@%s", username, host.Name)
		rec, err = recorder.New(recDir, sessionID, title, 80, 24)
		if err != nil {
			slog.Warn("WS failed to start recording", "err", err)
		} else if len(h.EncryptionKey) > 0 {
			rec.EncryptionKey = h.EncryptionKey
		}
	}

	recordingPath := ""
	if rec != nil {
		recordingPath = rec.Path()
	}
	dbSession := &models.Session{
		ID:        sessionID,
		UserID:    userID,
		Username:  username,
		HostID:    host.ID,
		HostName:  host.Name,
		HostAddr:  fmt.Sprintf("%s:%d", host.Hostname, port),
		Protocol:  "SSH",
		Recording: recordingPath,
		Reason:    reason,
	}
	if err := h.Sessions.Create(dbSession); err != nil {
		slog.Warn("WS failed to record session", "err", err)
	}

	detail := fmt.Sprintf("opened SSH session to %s", host.Name)
	if reason != "" {
		detail += "; reason: " + reason
	}
	h.Audit.Log(&models.AuditEntry{
		Action:    "connect",
		UserID:    userID,
		Username:  username,
		TargetID:  host.ID,
		Target:    host.Name,
		Detail:    detail,
		SourceIP:  sourceIP,
		SessionID: sessionID,
		Reason:    reason,
	})

	sendWSOutput(ws, fmt.Sprintf("\x1b[32mConnected to %s (session %s)\x1b[0m\r\n", host.Name, sessionID))

	wsDone := make(chan struct{})

	var inactivityTimeout time.Duration
	if h.Config.SSH.InactivityTimeout != "" && h.Config.SSH.InactivityTimeout != "0" {
		if d, err := time.ParseDuration(h.Config.SSH.InactivityTimeout); err == nil && d > 0 {
			inactivityTimeout = d
		}
	}
	activityChan := make(chan struct{}, 1)
	inactivityExpired := make(chan struct{})
	if inactivityTimeout > 0 {
		go func() {
			timer := time.NewTimer(inactivityTimeout)
			defer timer.Stop()
			done := proxySession.Done()
			for {
				select {
				case <-activityChan:
					if !timer.Stop() {
						<-timer.C
					}
					timer.Reset(inactivityTimeout)
				case <-timer.C:
					close(inactivityExpired)
					return
				case <-done:
					return
				}
			}
		}()
		select {
		case activityChan <- struct{}{}:
		default:
		}
	}

	// WS → SSH
	go func() {
		defer close(wsDone)
		for {
			_, raw, err := ws.ReadMessage()
			if err != nil {
				return
			}
			select {
			case activityChan <- struct{}{}:
			default:
			}

			var msg wsMessage
			if err := json.Unmarshal(raw, &msg); err != nil {
				proxySession.Write(raw)
				continue
			}

			switch msg.Type {
			case "input":
				var input wsInputData
				if err := json.Unmarshal(msg.Data, &input); err == nil {
					inputBytes := []byte(input.Data)
					proxySession.Write(inputBytes)
					if rec != nil {
						rec.WriteInput(inputBytes)
					}
				}
			case "resize":
				var resize wsResizeData
				if err := json.Unmarshal(msg.Data, &resize); err == nil && resize.Cols > 0 && resize.Rows > 0 {
					proxySession.Resize(resize.Cols, resize.Rows)
					if rec != nil {
						rec.Resize(resize.Cols, resize.Rows)
					}
				}
			case "ping":
			}
		}
	}()

	// SSH → WS
	sshOut := proxySession.Read()
	sshDone := proxySession.Done()

	bytesTicker := time.NewTicker(5 * time.Second)
	defer bytesTicker.Stop()

loop:
	for {
		select {
		case data, ok := <-sshOut:
			if !ok {
				break loop
			}
			select {
			case activityChan <- struct{}{}:
			default:
			}
			if rec != nil {
				rec.WriteOutput(data)
			}
			h.SSHManager.Watchers.Broadcast(sessionID, data)
			if err := sendWSOutput(ws, string(data)); err != nil {
				break loop
			}

		case <-sshDone:
			sendWSOutput(ws, "\r\n\x1b[33mSession ended.\x1b[0m\r\n")
			break loop

		case <-wsDone:
			break loop

		case <-inactivityExpired:
			sendWSOutput(ws, "\r\n\x1b[33mSession closed due to inactivity.\x1b[0m\r\n")
			proxySession.Close()
			break loop

		case <-bytesTicker.C:
			h.Sessions.UpdateBytes(sessionID, proxySession.BytesTX(), proxySession.BytesRX())
		}
	}

	metrics.SSHDisconnects.Add(1)
	metrics.SessionsActive.Add(-1)
	proxySession.Close()

	if rec != nil {
		rec.Close()
	}

	h.Sessions.UpdateBytes(sessionID, proxySession.BytesTX(), proxySession.BytesRX())
	h.Sessions.Close(sessionID)
	h.SSHManager.Watchers.CloseSession(sessionID)

	h.Audit.Log(&models.AuditEntry{
		Action:    "disconnect",
		UserID:    userID,
		Username:  username,
		TargetID:  host.ID,
		Target:    host.Name,
		Detail:    fmt.Sprintf("closed session to %s", host.Name),
		SourceIP:  sourceIP,
		SessionID: sessionID,
	})

	slog.Info("WS session ended", "session_id", sessionID, "user", username, "host", host.Name, "tx", proxySession.BytesTX(), "rx", proxySession.BytesRX())
}

func sendWSOutput(ws *websocket.Conn, data string) error {
	msg := map[string]string{
		"type": "output",
		"data": data,
	}
	return ws.WriteJSON(msg)
}

// Streams read-only terminal output for session watching.
type WatchSessionHandler struct {
	SSHManager *sshpkg.SessionManager
	Audit      *models.AuditStore
}

func (h *WatchSessionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "sessionId")

	ps := h.SSHManager.Get(sessionID)
	if ps == nil {
		http.Error(w, "session not found or not active", http.StatusNotFound)
		return
	}

	user := UserFromContext(r.Context())
	userID := "unknown"
	username := "anonymous"
	if user != nil {
		userID = user.ID
		username = user.Username
	}

	// owner or admin only
	if user != nil && user.Role != "platform-admin" && user.ID != ps.UserID {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Warn("WATCH upgrade failed", "err", err)
		return
	}

	ws.SetReadLimit(4096)

	watcherID, err := id.Short()
	if err != nil {
		slog.Error("failed to generate watcher id", "err", err)
		ws.Close()
		return
	}
	watcher := sshpkg.NewWatcher(watcherID, ws)

	h.SSHManager.Watchers.AddWatcher(sessionID, watcher)

	h.Audit.Log(&models.AuditEntry{
		Action:    "watch",
		UserID:    userID,
		Username:  username,
		TargetID:  ps.HostID,
		Target:    ps.HostName,
		Detail:    fmt.Sprintf("started watching session %s (%s@%s)", sessionID, ps.Username, ps.HostName),
		SourceIP:  r.RemoteAddr,
		SessionID: sessionID,
	})

	sendWSOutput(ws, fmt.Sprintf("\x1b[33m[watching session %s — %s@%s (read-only)]\x1b[0m\r\n", sessionID, ps.Username, ps.HostName))

	slog.Info("WATCH started", "user", username, "session_id", sessionID, "target", ps.Username+"@"+ps.HostName)

	for {
		_, _, err := ws.ReadMessage()
		if err != nil {
			break
		}
	}

	watcher.Close()
	slog.Info("WATCH stopped", "user", username, "session_id", sessionID)
}
