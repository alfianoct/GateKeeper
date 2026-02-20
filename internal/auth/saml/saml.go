package saml

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"

	"github.com/judsenb/gatekeeper/internal/models"
	"github.com/judsenb/gatekeeper/internal/secrets"
)

type UserInfo struct {
	NameID      string
	Username    string
	DisplayName string
	Groups      []string
}

type Config struct {
	IDPMetadataURL  string
	EntityID        string
	ACSURL          string
	UsernameAttr    string // e.g. "uid", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
	DisplayNameAttr string
	GroupsAttr      string // e.g. "memberOf", "groups"
}

func LoadConfig(s *models.SettingStore) Config {
	return Config{
		IDPMetadataURL:  strings.TrimSpace(s.Get(models.SettingSAMLIDPMetadataURL, "")),
		EntityID:        strings.TrimSpace(s.Get(models.SettingSAMLEntityID, "")),
		ACSURL:          strings.TrimSpace(s.Get(models.SettingSAMLACSURL, "")),
		UsernameAttr:    s.Get(models.SettingSAMLUsernameAttr, ""),
		DisplayNameAttr: s.Get(models.SettingSAMLDisplayNameAttr, ""),
		GroupsAttr:      s.Get(models.SettingSAMLGroupsAttr, ""),
	}
}

// Manages the SAML SP, re-inits when settings change.
type Provider struct {
	mu  sync.RWMutex
	sp  *saml.ServiceProvider
	cfg Config
}

func NewProvider() *Provider {
	return &Provider{}
}

func (p *Provider) IsConfigured() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.sp != nil
}

// Re-reads settings, re-inits SP if config changed.
func (p *Provider) Refresh(settings *models.SettingStore, _ secrets.Backend) error {
	cfg := LoadConfig(settings)

	if cfg.IDPMetadataURL == "" || cfg.EntityID == "" || cfg.ACSURL == "" {
		return fmt.Errorf("SAML IdP metadata URL, entity ID, and ACS URL are required")
	}

	p.mu.RLock()
	unchanged := p.sp != nil &&
		p.cfg.IDPMetadataURL == cfg.IDPMetadataURL &&
		p.cfg.EntityID == cfg.EntityID &&
		p.cfg.ACSURL == cfg.ACSURL
	p.mu.RUnlock()

	if unchanged {
		return nil
	}

	idpMeta, err := fetchIDPMetadata(cfg.IDPMetadataURL)
	if err != nil {
		return fmt.Errorf("fetch IdP metadata: %w", err)
	}

	acsURL, err := url.Parse(cfg.ACSURL)
	if err != nil {
		return fmt.Errorf("parse ACS URL %q: %w", cfg.ACSURL, err)
	}

	entityURL, err := url.Parse(cfg.EntityID)
	if err != nil {
		return fmt.Errorf("parse entity ID %q: %w", cfg.EntityID, err)
	}

	certPEM := settings.Get(models.SettingSAMLSPCert, "")
	keyPEM := settings.Get(models.SettingSAMLSPKey, "")

	var spCert tls.Certificate
	if certPEM != "" && keyPEM != "" {
		certDER, _ := base64.StdEncoding.DecodeString(certPEM)
		keyDER, _ := base64.StdEncoding.DecodeString(keyPEM)
		if len(certDER) > 0 && len(keyDER) > 0 {
			spCert, err = tls.X509KeyPair(certDER, keyDER)
			if err != nil {
				slog.Warn("SAML SP cert/key invalid, generating new pair", "err", err)
				certPEM = ""
			}
		}
	}

	if certPEM == "" {
		spCert, err = generateSPCert(cfg.EntityID)
		if err != nil {
			return fmt.Errorf("generate SP certificate: %w", err)
		}
		certPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: spCert.Certificate[0]})
		keyDER, _ := x509.MarshalPKCS8PrivateKey(spCert.PrivateKey)
		keyPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		_ = settings.Set(models.SettingSAMLSPCert, base64.StdEncoding.EncodeToString(certPEMBytes))
		_ = settings.Set(models.SettingSAMLSPKey, base64.StdEncoding.EncodeToString(keyPEMBytes))
	}

	var x509Cert *x509.Certificate
	if len(spCert.Certificate) > 0 {
		x509Cert, _ = x509.ParseCertificate(spCert.Certificate[0])
	}

	sp := saml.ServiceProvider{
		EntityID:          entityURL.String(),
		Key:               spCert.PrivateKey.(*rsa.PrivateKey),
		Certificate:       x509Cert,
		IDPMetadata:       idpMeta,
		AcsURL:            *acsURL,
		AllowIDPInitiated: true,
	}

	p.mu.Lock()
	p.sp = &sp
	p.cfg = cfg
	p.mu.Unlock()

	slog.Info("SAML service provider initialised", "entity_id", cfg.EntityID, "acs_url", cfg.ACSURL)
	return nil
}

// Builds the AuthnRequest redirect URL for the IdP.
func (p *Provider) MakeAuthenticationRequest(relayState string) (*url.URL, error) {
	p.mu.RLock()
	sp := p.sp
	p.mu.RUnlock()

	if sp == nil {
		return nil, fmt.Errorf("SAML provider not configured")
	}

	authReq, err := sp.MakeAuthenticationRequest(
		sp.GetSSOBindingLocation(saml.HTTPRedirectBinding),
		saml.HTTPRedirectBinding,
		saml.HTTPPostBinding,
	)
	if err != nil {
		return nil, fmt.Errorf("create AuthnRequest: %w", err)
	}

	redirectURL, err := authReq.Redirect(relayState, sp)
	if err != nil {
		return nil, fmt.Errorf("build redirect URL: %w", err)
	}

	return redirectURL, nil
}

// Validates the SAML response and pulls user info out of the assertion.
func (p *Provider) ParseResponse(r *http.Request) (*UserInfo, error) {
	p.mu.RLock()
	sp := p.sp
	cfg := p.cfg
	p.mu.RUnlock()

	if sp == nil {
		return nil, fmt.Errorf("SAML provider not configured")
	}

	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("parse form: %w", err)
	}

	assertion, err := sp.ParseResponse(r, []string{""})
	if err != nil {
		return nil, fmt.Errorf("SAML response validation failed: %w", err)
	}

	info := &UserInfo{}

	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		info.NameID = assertion.Subject.NameID.Value
	}

	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			vals := attrValues(attr)
			if len(vals) == 0 {
				continue
			}
			name := attr.Name
			if name == cfg.UsernameAttr || (cfg.UsernameAttr == "" && isUsernameAttr(name)) {
				info.Username = vals[0]
			}
			if name == cfg.DisplayNameAttr || (cfg.DisplayNameAttr == "" && isDisplayNameAttr(name)) {
				info.DisplayName = vals[0]
			}
			if name == cfg.GroupsAttr || (cfg.GroupsAttr == "" && isGroupsAttr(name)) {
				info.Groups = append(info.Groups, vals...)
			}
		}
	}

	if info.Username == "" {
		info.Username = info.NameID
	}
	if info.DisplayName == "" {
		info.DisplayName = info.Username
	}

	return info, nil
}

func (p *Provider) Metadata() ([]byte, error) {
	p.mu.RLock()
	sp := p.sp
	p.mu.RUnlock()

	if sp == nil {
		return nil, fmt.Errorf("SAML provider not configured")
	}

	meta := sp.Metadata()
	return xml.MarshalIndent(meta, "", "  ")
}

func fetchIDPMetadata(metadataURL string) (*saml.EntityDescriptor, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("IdP metadata returned %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	meta, err := samlsp.ParseMetadata(data)
	if err != nil {
		return nil, fmt.Errorf("parse IdP metadata: %w", err)
	}

	return meta, nil
}

func generateSPCert(entityID string) (tls.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               spSubject(entityID),
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	return selfSign(tmpl)
}

func attrValues(attr saml.Attribute) []string {
	var vals []string
	for _, v := range attr.Values {
		if s := strings.TrimSpace(v.Value); s != "" {
			vals = append(vals, s)
		}
	}
	return vals
}

func isUsernameAttr(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "username") ||
		strings.Contains(lower, "name/emailaddress") ||
		strings.Contains(lower, "claims/name") ||
		lower == "uid" || lower == "samaccountname"
}

func isDisplayNameAttr(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "displayname") ||
		strings.Contains(lower, "claims/givenname") ||
		lower == "cn"
}

func isGroupsAttr(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "group") ||
		strings.Contains(lower, "memberof") ||
		strings.Contains(lower, "role")
}
