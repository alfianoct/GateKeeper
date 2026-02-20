package ssh

import (
	"log/slog"
	"sync"

	"github.com/gorilla/websocket"
)

// Watcher is a read-only viewer piggybacking on someone else's session.
type Watcher struct {
	ID   string
	Conn *websocket.Conn
	done chan struct{}
	once sync.Once
}

func NewWatcher(id string, conn *websocket.Conn) *Watcher {
	return &Watcher{
		ID:   id,
		Conn: conn,
		done: make(chan struct{}),
	}
}

func (w *Watcher) Close() {
	w.once.Do(func() {
		close(w.done)
		w.Conn.Close()
	})
}

func (w *Watcher) Done() <-chan struct{} {
	return w.done
}

// WatcherHub fans out session output to all connected watchers.
type WatcherHub struct {
	mu       sync.RWMutex
	watchers map[string]map[string]*Watcher // sessionID → watcherID → Watcher
}

func NewWatcherHub() *WatcherHub {
	return &WatcherHub{
		watchers: make(map[string]map[string]*Watcher),
	}
}

func (h *WatcherHub) AddWatcher(sessionID string, w *Watcher) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.watchers[sessionID] == nil {
		h.watchers[sessionID] = make(map[string]*Watcher)
	}
	h.watchers[sessionID][w.ID] = w
	slog.Info("watcher attached", "watcher_id", w.ID, "session_id", sessionID, "total", len(h.watchers[sessionID]))

	go func() {
		<-w.Done()
		h.RemoveWatcher(sessionID, w.ID)
	}()
}

func (h *WatcherHub) RemoveWatcher(sessionID, watcherID string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if ws, ok := h.watchers[sessionID]; ok {
		if w, exists := ws[watcherID]; exists {
			w.Close()
			delete(ws, watcherID)
			slog.Info("watcher detached", "watcher_id", watcherID, "session_id", sessionID)
		}
		if len(ws) == 0 {
			delete(h.watchers, sessionID)
		}
	}
}

func (h *WatcherHub) Broadcast(sessionID string, data []byte) {
	h.mu.RLock()
	ws := h.watchers[sessionID]
	if len(ws) == 0 {
		h.mu.RUnlock()
		return
	}
	// snapshot so we don't hold the lock while doing websocket writes
	watchers := make([]*Watcher, 0, len(ws))
	for _, w := range ws {
		watchers = append(watchers, w)
	}
	h.mu.RUnlock()

	msg := map[string]string{
		"type": "output",
		"data": string(data),
	}

	for _, w := range watchers {
		select {
		case <-w.Done():
			continue
		default:
			if err := w.Conn.WriteJSON(msg); err != nil {
				w.Close()
			}
		}
	}
}

func (h *WatcherHub) CloseSession(sessionID string) {
	h.mu.Lock()
	ws := h.watchers[sessionID]
	delete(h.watchers, sessionID)
	h.mu.Unlock()

	for _, w := range ws {
		w.Conn.WriteJSON(map[string]string{
			"type": "output",
			"data": "\r\n\x1b[33m[session ended]\x1b[0m\r\n",
		})
		w.Close()
	}
}

func (h *WatcherHub) WatcherCount(sessionID string) int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.watchers[sessionID])
}
