package tlsgen

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// CertReloader swaps TLS certs at runtime without a restart.
type CertReloader struct {
	certPath string
	keyPath  string

	mu      sync.RWMutex
	cert    *tls.Certificate
	leaf    *x509.Certificate
	modTime time.Time

	stopCh chan struct{}
}

func NewCertReloader(certPath, keyPath string) (*CertReloader, error) {
	r := &CertReloader{
		certPath: certPath,
		keyPath:  keyPath,
		stopCh:   make(chan struct{}),
	}
	if err := r.Reload(); err != nil {
		return nil, fmt.Errorf("initial TLS load: %w", err)
	}
	return r, nil
}

func (r *CertReloader) Reload() error {
	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return fmt.Errorf("load keypair: %w", err)
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse leaf cert: %w", err)
	}
	cert.Leaf = leaf

	r.mu.Lock()
	r.cert = &cert
	r.leaf = leaf
	r.mu.Unlock()

	slog.Info("TLS certificate loaded",
		"serial", fmt.Sprintf("%x", leaf.SerialNumber),
		"subject", leaf.Subject.CommonName,
		"expires", leaf.NotAfter.Format(time.RFC3339),
		"issuer", leaf.Issuer.CommonName,
	)
	return nil
}

func (r *CertReloader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cert, nil
}

// TLSConfig wires up GetCertificate. min version is TLS 1.2, don't lower it.
func (r *CertReloader) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: r.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}
}

func (r *CertReloader) CertExpiry() time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.leaf == nil {
		return time.Time{}
	}
	return r.leaf.NotAfter
}

func (r *CertReloader) CertSerial() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.leaf == nil {
		return ""
	}
	return fmt.Sprintf("%x", r.leaf.SerialNumber)
}

// Watch polls for cert changes. polling because fsnotify is broken on half the platforms.
func (r *CertReloader) Watch(interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	go r.pollLoop(interval)
}

func (r *CertReloader) Stop() {
	select {
	case <-r.stopCh:
	default:
		close(r.stopCh)
	}
}

func (r *CertReloader) pollLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	r.mu.Lock()
	r.modTime = latestModTime(r.certPath, r.keyPath)
	r.mu.Unlock()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			mt := latestModTime(r.certPath, r.keyPath)
			r.mu.RLock()
			changed := !mt.Equal(r.modTime) && !mt.IsZero()
			r.mu.RUnlock()

			if changed {
				slog.Info("TLS certificate file changed, reloading",
					"cert", r.certPath, "key", r.keyPath)
				if err := r.Reload(); err != nil {
					slog.Error("TLS hot-reload failed", "err", err)
					continue
				}
				r.mu.Lock()
				r.modTime = mt
				r.mu.Unlock()
			}
		}
	}
}

func latestModTime(paths ...string) time.Time {
	var latest time.Time
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if fi.ModTime().After(latest) {
			latest = fi.ModTime()
		}
	}
	return latest
}
