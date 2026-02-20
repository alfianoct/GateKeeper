package ssh

import (
	"log/slog"
	"sync"
)

// SessionManager is the in-memory registry of live SSH sessions.
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*ProxySession // keyed by session ID
	Watchers *WatcherHub
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*ProxySession),
		Watchers: NewWatcherHub(),
	}
}

func (m *SessionManager) Register(ps *ProxySession) {
	m.mu.Lock()
	m.sessions[ps.ID] = ps
	m.mu.Unlock()
	slog.Info("session registered", "session_id", ps.ID, "user", ps.Username, "addr", ps.HostAddr)

	// auto-cleanup when the session dies
	go func() {
		<-ps.Done()
		m.Unregister(ps.ID)
	}()
}

func (m *SessionManager) Unregister(id string) {
	m.mu.Lock()
	if ps, ok := m.sessions[id]; ok {
		delete(m.sessions, id)
		slog.Info("session unregistered", "session_id", id, "user", ps.Username, "addr", ps.HostAddr)
	}
	m.mu.Unlock()
}

func (m *SessionManager) Get(id string) *ProxySession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[id]
}

func (m *SessionManager) Kill(id string) bool {
	m.mu.RLock()
	ps, ok := m.sessions[id]
	m.mu.RUnlock()
	if !ok {
		return false
	}
	ps.Close()
	return true
}

func (m *SessionManager) KillAll() int {
	m.mu.RLock()
	ids := make([]string, 0, len(m.sessions))
	for id := range m.sessions {
		ids = append(ids, id)
	}
	m.mu.RUnlock()

	for _, id := range ids {
		m.Kill(id)
	}
	return len(ids)
}

func (m *SessionManager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

func (m *SessionManager) List() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ids := make([]string, 0, len(m.sessions))
	for id := range m.sessions {
		ids = append(ids, id)
	}
	return ids
}
