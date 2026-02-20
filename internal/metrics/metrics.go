package metrics

import (
	"sync/atomic"
	"time"
)

var (
	LoginsSuccess  atomic.Uint64
	LoginsFailed   atomic.Uint64
	SSHConnects    atomic.Uint64
	SSHDisconnects atomic.Uint64
	SessionsActive atomic.Int64  // current active SSH sessions
	AuditEvents    atomic.Uint64 // total audit events (approximate)
)

type Snapshot struct {
	LoginsSuccess  uint64    `json:"logins_success"`
	LoginsFailed   uint64    `json:"logins_failed"`
	SSHConnects    uint64    `json:"ssh_connects"`
	SSHDisconnects uint64    `json:"ssh_disconnects"`
	SessionsActive int64     `json:"sessions_active"`
	AuditEvents    uint64    `json:"audit_events"`
	At             time.Time `json:"at"`
}

func GetSnapshot() Snapshot {
	return Snapshot{
		LoginsSuccess:  LoginsSuccess.Load(),
		LoginsFailed:   LoginsFailed.Load(),
		SSHConnects:    SSHConnects.Load(),
		SSHDisconnects: SSHDisconnects.Load(),
		SessionsActive: SessionsActive.Load(),
		AuditEvents:    AuditEvents.Load(),
		At:             time.Now().UTC(),
	}
}
