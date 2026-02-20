package audit

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/judsenb/gatekeeper/internal/instance"
)

type Event struct {
	Timestamp  string `json:"timestamp"`
	Action     string `json:"action"`
	UserID     string `json:"user_id,omitempty"`
	Username   string `json:"username,omitempty"`
	TargetID   string `json:"target_id,omitempty"`
	Target     string `json:"target,omitempty"`
	Detail     string `json:"detail,omitempty"`
	SourceIP   string `json:"source_ip,omitempty"`
	SessionID  string `json:"session_id,omitempty"`
	Reason     string `json:"reason,omitempty"`
	InstanceID string `json:"instance_id"`
}

type Exporter interface {
	Export(event Event) error
	Name() string
}

type noopExporter struct{}

func (noopExporter) Export(Event) error { return nil }
func (noopExporter) Name() string       { return "noop" }

func NewNoop() Exporter { return noopExporter{} }

// WebhookExporter POSTs events as JSON, optionally HMAC-signed.
type WebhookExporter struct {
	URL    string
	Secret string
	Client *http.Client
}

func NewWebhook(url, secret string) *WebhookExporter {
	return &WebhookExporter{
		URL:    url,
		Secret: secret,
		Client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (w *WebhookExporter) Name() string { return "webhook" }

func (w *WebhookExporter) Export(event Event) error {
	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("webhook marshal: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "GateKeeper-Audit/1.0")

	if w.Secret != "" {
		mac := hmac.New(sha256.New, []byte(w.Secret))
		mac.Write(body)
		sig := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-GateKeeper-Signature", "sha256="+sig)
	}

	resp, err := w.Client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook send: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// SyslogExporter sends RFC 5424 messages over UDP or TCP.
type SyslogExporter struct {
	Addr     string // "udp://host:514" or "tcp://host:514"
	Facility int    // syslog facility (default 1 = user)
	network  string
	address  string
}

func NewSyslog(addr string, facility int) *SyslogExporter {
	network := "udp"
	address := addr
	if strings.HasPrefix(addr, "tcp://") {
		network = "tcp"
		address = strings.TrimPrefix(addr, "tcp://")
	} else if strings.HasPrefix(addr, "udp://") {
		address = strings.TrimPrefix(addr, "udp://")
	}
	if facility <= 0 {
		facility = 1
	}
	return &SyslogExporter{
		Addr:     addr,
		Facility: facility,
		network:  network,
		address:  address,
	}
}

func (s *SyslogExporter) Name() string { return "syslog" }

func (s *SyslogExporter) Export(event Event) error {
	// severity 6 = informational per RFC 5424
	pri := s.Facility*8 + 6
	hostname, _ := instance.ID(), ""
	ts := event.Timestamp
	if ts == "" {
		ts = time.Now().UTC().Format(time.RFC3339)
	}

	msg := fmt.Sprintf("<%d>1 %s %s GateKeeper - - [audit@0 action=%q user=%q target=%q detail=%q ip=%q instance_id=%q] %s %s",
		pri, ts, hostname, event.Action, event.Username, event.Target,
		event.Detail, event.SourceIP, event.InstanceID,
		event.Action, event.Detail)

	conn, err := net.DialTimeout(s.network, s.address, 5*time.Second)
	if err != nil {
		return fmt.Errorf("syslog connect %s: %w", s.address, err)
	}
	defer conn.Close()
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))

	_, err = fmt.Fprint(conn, msg)
	return err
}

const (
	dispatchBuffer = 256
	maxRetries     = 3
	initialBackoff = 500 * time.Millisecond
)

// Dispatcher async-fans events to exporters with retry. non-blocking.
type Dispatcher struct {
	mu        sync.RWMutex
	exporters []Exporter
	ch        chan Event
	done      chan struct{}
}

func NewDispatcher() *Dispatcher {
	d := &Dispatcher{
		ch:   make(chan Event, dispatchBuffer),
		done: make(chan struct{}),
	}
	go d.worker()
	return d
}

// SetExporters hot-swaps the exporter list without restart.
func (d *Dispatcher) SetExporters(exporters []Exporter) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.exporters = exporters
}

// Send is non-blocking. drops events if the buffer is full, sorry.
func (d *Dispatcher) Send(event Event) {
	event.InstanceID = instance.ID()
	select {
	case d.ch <- event:
	default:
		slog.Warn("audit export buffer full, event dropped", "action", event.Action)
	}
}

func (d *Dispatcher) Stop() {
	close(d.ch)
	<-d.done
}

func (d *Dispatcher) worker() {
	defer close(d.done)
	for event := range d.ch {
		d.mu.RLock()
		exporters := d.exporters
		d.mu.RUnlock()

		for _, exp := range exporters {
			d.exportWithRetry(exp, event)
		}
	}
}

func (d *Dispatcher) exportWithRetry(exp Exporter, event Event) {
	backoff := initialBackoff
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if err := exp.Export(event); err != nil {
			if attempt < maxRetries {
				slog.Warn("audit export failed, retrying",
					"exporter", exp.Name(), "attempt", attempt+1, "err", err)
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			slog.Error("audit export failed permanently",
				"exporter", exp.Name(), "action", event.Action, "err", err)
		}
		return
	}
}

func TestWebhook(url, secret string) error {
	exp := NewWebhook(url, secret)
	return exp.Export(Event{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Action:     "test",
		Username:   "system",
		Detail:     "GateKeeper audit webhook test event",
		InstanceID: instance.ID(),
	})
}
