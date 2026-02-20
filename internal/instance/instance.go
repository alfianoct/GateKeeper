package instance

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"sync"
	"time"
)

var (
	mu        sync.RWMutex
	id        string
	startedAt time.Time
)

// Init sets the instance ID. Uses GK_INSTANCE_ID or hostname + random suffix.
func Init() {
	mu.Lock()
	defer mu.Unlock()

	startedAt = time.Now().UTC()

	if v := os.Getenv("GK_INSTANCE_ID"); v != "" {
		id = v
		return
	}

	host, _ := os.Hostname()
	if host == "" {
		host = "gk"
	}

	suffix := make([]byte, 4)
	rand.Read(suffix)
	id = host + "-" + hex.EncodeToString(suffix)
}

func ID() string {
	mu.RLock()
	defer mu.RUnlock()
	return id
}

func StartedAt() time.Time {
	mu.RLock()
	defer mu.RUnlock()
	return startedAt
}

func Uptime() time.Duration {
	mu.RLock()
	defer mu.RUnlock()
	return time.Since(startedAt)
}
