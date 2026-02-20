package recorder

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/judsenb/gatekeeper/internal/crypto"
)

// magic header bytes so we know if the file is encrypted
var MagicHeader = []byte("GKENC1")

// Recorder captures terminal I/O as asciicast v2.
type Recorder struct {
	mu            sync.Mutex
	file          *os.File
	startTime     time.Time
	closed        bool
	path          string
	EncryptionKey []byte // If set (32 bytes), the file is encrypted on Close.
}

type header struct {
	Version   int               `json:"version"`
	Width     int               `json:"width"`
	Height    int               `json:"height"`
	Timestamp int64             `json:"timestamp"`
	Title     string            `json:"title,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
}

func New(dir, sessionID, title string, cols, rows int) (*Recorder, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create recordings dir: %w", err)
	}

	path := filepath.Join(dir, sessionID+".cast")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("create recording file: %w", err)
	}

	now := time.Now()
	hdr := header{
		Version:   2,
		Width:     cols,
		Height:    rows,
		Timestamp: now.Unix(),
		Title:     title,
		Env: map[string]string{
			"SHELL": "/bin/bash",
			"TERM":  "xterm-256color",
		},
	}

	hdrJSON, err := json.Marshal(hdr)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("marshal header: %w", err)
	}

	if _, err := fmt.Fprintf(f, "%s\n", hdrJSON); err != nil {
		f.Close()
		return nil, fmt.Errorf("write header: %w", err)
	}

	return &Recorder{
		file:      f,
		startTime: now,
		path:      path,
	}, nil
}

func (r *Recorder) WriteOutput(data []byte) {
	r.writeEvent("o", data)
}

func (r *Recorder) WriteInput(data []byte) {
	r.writeEvent("i", data)
}

// writeEvent writes [elapsed, type, data] per asciicast v2 spec
func (r *Recorder) writeEvent(eventType string, data []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed || r.file == nil {
		return
	}

	elapsed := time.Since(r.startTime).Seconds()
	dataJSON, _ := json.Marshal(string(data))
	fmt.Fprintf(r.file, "[%.6f, %q, %s]\n", elapsed, eventType, dataJSON)
}

func (r *Recorder) Resize(cols, rows int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed || r.file == nil {
		return
	}

	elapsed := time.Since(r.startTime).Seconds()
	resize := fmt.Sprintf(`{"cols":%d,"rows":%d}`, cols, rows)
	dataJSON, _ := json.Marshal(resize)
	fmt.Fprintf(r.file, "[%.6f, \"r\", %s]\n", elapsed, dataJSON)
}

// Close finishes the file. if we have an encryption key, re-read and encrypt in place.
func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil
	}
	r.closed = true
	if err := r.file.Close(); err != nil {
		return err
	}

	if len(r.EncryptionKey) == crypto.KeySize {
		return encryptFileInPlace(r.path, r.EncryptionKey)
	}
	return nil
}

func encryptFileInPlace(path string, key []byte) error {
	plaintext, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read recording for encryption: %w", err)
	}
	ct, err := crypto.EncryptBytes(key, plaintext)
	if err != nil {
		return fmt.Errorf("encrypt recording: %w", err)
	}
	out := append(MagicHeader, ct...)
	return os.WriteFile(path, out, 0600)
}

func (r *Recorder) Path() string {
	return r.path
}

// ReadRecording transparently decrypts if the file has the magic header.
func ReadRecording(path string, key []byte) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(data, MagicHeader) {
		return data, nil
	}
	if len(key) != crypto.KeySize {
		return nil, fmt.Errorf("recording is encrypted but no encryption key is configured")
	}
	ct := data[len(MagicHeader):]
	return crypto.DecryptBytes(key, ct)
}

// EncryptExistingFile encrypts a plaintext recording in place (for key rotation).
func EncryptExistingFile(path string, key []byte) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if bytes.HasPrefix(data, MagicHeader) {
		return nil // already encrypted
	}
	return encryptFileInPlace(path, key)
}

func ReEncryptFile(path string, oldKey, newKey []byte) error {
	plaintext, err := ReadRecording(path, oldKey)
	if err != nil {
		return err
	}
	ct, err := crypto.EncryptBytes(newKey, plaintext)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(MagicHeader, ct...), 0600)
}
