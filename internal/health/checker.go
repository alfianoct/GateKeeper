package health

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/judsenb/gatekeeper/internal/config"
	"github.com/judsenb/gatekeeper/internal/models"
)

// Checker pings hosts on a timer and flips their online bit.
type Checker struct {
	hosts    *models.HostStore
	interval time.Duration
	timeout  time.Duration
	stopCh   chan struct{}
	once     sync.Once
}

func NewChecker(hosts *models.HostStore, cfg config.HealthConfig) *Checker {
	interval := 60 * time.Second
	if d, err := time.ParseDuration(cfg.CheckInterval); err == nil && d > 0 {
		interval = d
	}
	timeout := 5 * time.Second
	if d, err := time.ParseDuration(cfg.Timeout); err == nil && d > 0 {
		timeout = d
	}

	return &Checker{
		hosts:    hosts,
		interval: interval,
		timeout:  timeout,
		stopCh:   make(chan struct{}),
	}
}

func (c *Checker) Start() {
	go c.loop()
}

func (c *Checker) Stop() {
	c.once.Do(func() {
		close(c.stopCh)
	})
}

func (c *Checker) loop() {
	// check immediately so the dashboard isn't stale on first load
	c.checkAll()

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.checkAll()
		case <-c.stopCh:
			slog.Info("health checker stopped")
			return
		}
	}
}

func (c *Checker) checkAll() {
	hostList, err := c.hosts.List()
	if err != nil {
		slog.Warn("health check failed to list hosts", "err", err)
		return
	}

	if len(hostList) == 0 {
		return
	}

	type result struct {
		id     string
		online bool
	}

	results := make(chan result, len(hostList))
	var wg sync.WaitGroup
	for i := range hostList {
		wg.Add(1)
		go func(h models.Host) {
			defer wg.Done()
			online := c.probe(h.Hostname, h.Port)
			results <- result{id: h.ID, online: online}
		}(hostList[i])
	}
	wg.Wait()
	close(results)

	onlineCount := 0
	for r := range results {
		if r.online {
			onlineCount++
		}
		if err := c.hosts.SetOnline(r.id, r.online); err != nil {
			slog.Warn("health check failed to update host", "host_id", r.id, "err", err)
		}
	}

	slog.Info("health check complete", "online", onlineCount, "total", len(hostList))
}

func (c *Checker) probe(host string, port int) bool {
	if port == 0 {
		port = 22
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, c.timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
