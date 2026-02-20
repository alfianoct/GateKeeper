package api

import (
	"net/http"
	"time"

	"github.com/judsenb/gatekeeper/internal/instance"
	"github.com/judsenb/gatekeeper/internal/metrics"
	"github.com/judsenb/gatekeeper/internal/models"
	tlsgen "github.com/judsenb/gatekeeper/internal/tls"
)

type DashboardHandler struct {
	Hosts         *models.HostStore
	Sessions      *models.SessionStore
	Audit         *models.AuditStore
	Users         *models.UserStore
	Settings      *models.SettingStore
	TLS           *tlsgen.CertReloader
	DBDriver      string
	Mode          string
	EncryptionKey []byte
}

func (h *DashboardHandler) GetDashboard(w http.ResponseWriter, r *http.Request) {
	snap := metrics.GetSnapshot()

	hostsOnline, hostsTotal := h.hostCounts()
	usersTotal, usersActive24h := h.userCounts()

	resp := map[string]any{
		"logins_success":  snap.LoginsSuccess,
		"logins_failed":   snap.LoginsFailed,
		"ssh_connects":    snap.SSHConnects,
		"ssh_disconnects": snap.SSHDisconnects,
		"sessions_active": snap.SessionsActive,
		"audit_events":    snap.AuditEvents,
		"at":              snap.At,

		"hosts_online":     hostsOnline,
		"hosts_total":      hostsTotal,
		"users_total":      usersTotal,
		"users_active_24h": usersActive24h,

		"instance_id":     instance.ID(),
		"uptime_seconds":  int64(instance.Uptime().Seconds()),
		"deployment_mode": h.Mode,
		"db_driver":       h.DBDriver,

		"recent_activity": h.recentActivity(),
		"active_sessions": h.activeSessions(),
		"health":          h.systemHealth(),
	}

	jsonResponse(w, http.StatusOK, resp)
}

func (h *DashboardHandler) hostCounts() (online, total int) {
	hosts, err := h.Hosts.List()
	if err != nil {
		return 0, 0
	}
	total = len(hosts)
	for _, host := range hosts {
		if host.Online && !host.Disabled {
			online++
		}
	}
	return
}

func (h *DashboardHandler) userCounts() (total, active24h int) {
	users, err := h.Users.List()
	if err != nil {
		return 0, 0
	}
	total = len(users)
	cutoff := time.Now().Add(-24 * time.Hour)
	for _, u := range users {
		if u.LastLoginAt == nil {
			continue
		}
		if t, err := time.Parse(time.RFC3339, *u.LastLoginAt); err == nil && t.After(cutoff) {
			active24h++
		} else if t, err := time.Parse("2006-01-02 15:04:05", *u.LastLoginAt); err == nil && t.After(cutoff) {
			active24h++
		}
	}
	return
}

type activityEntry struct {
	Timestamp string `json:"timestamp"`
	Action    string `json:"action"`
	Username  string `json:"username"`
	Detail    string `json:"detail"`
	SourceIP  string `json:"source_ip"`
}

func (h *DashboardHandler) recentActivity() []activityEntry {
	entries, err := h.Audit.List("", 15, 0)
	if err != nil {
		return []activityEntry{}
	}
	out := make([]activityEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, activityEntry{
			Timestamp: e.Timestamp,
			Action:    e.Action,
			Username:  e.Username,
			Detail:    e.Detail,
			SourceIP:  e.SourceIP,
		})
	}
	return out
}

type sessionEntry struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	HostName    string `json:"host_name"`
	ConnectedAt string `json:"connected_at"`
	Protocol    string `json:"protocol"`
}

func (h *DashboardHandler) activeSessions() []sessionEntry {
	sessions, err := h.Sessions.ListActive()
	if err != nil {
		return []sessionEntry{}
	}
	limit := 5
	if len(sessions) < limit {
		limit = len(sessions)
	}
	out := make([]sessionEntry, 0, limit)
	for i := 0; i < limit; i++ {
		s := sessions[i]
		out = append(out, sessionEntry{
			ID:          s.ID,
			Username:    s.Username,
			HostName:    s.HostName,
			ConnectedAt: s.ConnectedAt,
			Protocol:    s.Protocol,
		})
	}
	return out
}

func (h *DashboardHandler) systemHealth() map[string]any {
	health := map[string]any{
		"encryption_enabled": len(h.EncryptionKey) > 0,
	}

	if h.TLS != nil {
		expiry := h.TLS.CertExpiry()
		health["tls_enabled"] = true
		if !expiry.IsZero() {
			health["tls_cert_expires"] = expiry.Format(time.RFC3339)
		}
	} else {
		health["tls_enabled"] = false
	}

	return health
}
