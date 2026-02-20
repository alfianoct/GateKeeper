package audit_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/judsenb/gatekeeper/internal/audit"
)

func TestWebhookExporter_SendsJSON(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		body, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	exp := audit.NewWebhook(srv.URL, "")
	event := audit.Event{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Action:    "user.login",
		Username:  "admin",
		Detail:    "test event",
	}

	if err := exp.Export(event); err != nil {
		t.Fatalf("export: %v", err)
	}

	var got audit.Event
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Action != "user.login" {
		t.Fatalf("expected action %q, got %q", "user.login", got.Action)
	}
	if got.Username != "admin" {
		t.Fatalf("expected username %q, got %q", "admin", got.Username)
	}
}

func TestWebhookExporter_HMACSigning(t *testing.T) {
	var gotSig string
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-GateKeeper-Signature")
		var err error
		body, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	secret := "test-webhook-secret"
	exp := audit.NewWebhook(srv.URL, secret)
	event := audit.Event{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Action:    "user.login",
	}

	if err := exp.Export(event); err != nil {
		t.Fatalf("export: %v", err)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if gotSig != expected {
		t.Fatalf("signature mismatch\n  got:  %s\n  want: %s", gotSig, expected)
	}
}

func TestWebhookExporter_ErrorOnBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	exp := audit.NewWebhook(srv.URL, "")
	err := exp.Export(audit.Event{Action: "test"})
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("error should mention status code, got: %v", err)
	}
}

type mockExporter struct {
	events chan audit.Event
}

func (m *mockExporter) Export(e audit.Event) error {
	m.events <- e
	return nil
}

func (m *mockExporter) Name() string { return "mock" }

func TestDispatcher_SendAndReceive(t *testing.T) {
	d := audit.NewDispatcher()
	defer d.Stop()

	mock := &mockExporter{events: make(chan audit.Event, 8)}
	d.SetExporters([]audit.Exporter{mock})

	d.Send(audit.Event{Action: "test.event", Detail: "hello"})

	select {
	case e := <-mock.events:
		if e.Action != "test.event" {
			t.Fatalf("expected action %q, got %q", "test.event", e.Action)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestDispatcher_DropsWhenFull(t *testing.T) {
	d := audit.NewDispatcher()

	// don't set any exporters so nothing drains the channel
	for i := 0; i < 300; i++ {
		d.Send(audit.Event{Action: "flood"})
	}

	d.Stop()
}

func TestDispatcher_Stop(t *testing.T) {
	d := audit.NewDispatcher()
	done := make(chan struct{})
	go func() {
		d.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("dispatcher stop did not complete within 2s")
	}
}
