package ldap

import (
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/judsenb/gatekeeper/internal/models"
)

type Config struct {
	URL             string // ldap:// or ldaps://
	BindDN          string
	BindPassword    string
	UserBase        string
	UserFilter      string // e.g. "(uid=%s)" — %s gets the username
	GroupAttr       string // e.g. "memberOf"
	UsernameAttr    string // e.g. "uid", "sAMAccountName"
	DisplayNameAttr string // e.g. "displayName", "cn"
}

type UserInfo struct {
	DN          string
	Username    string
	DisplayName string
	Groups      []string
}

func LoadConfig(s *models.SettingStore, bindPassword string) Config {
	if bindPassword == "" {
		bindPassword = s.Get(models.SettingLDAPBindPassword, "")
	}
	return Config{
		URL:             strings.TrimSpace(s.Get(models.SettingLDAPURL, "")),
		BindDN:          strings.TrimSpace(s.Get(models.SettingLDAPBindDN, "")),
		BindPassword:    bindPassword,
		UserBase:        strings.TrimSpace(s.Get(models.SettingLDAPUserBase, "")),
		UserFilter:      s.Get(models.SettingLDAPUserFilter, "(uid=%s)"),
		GroupAttr:       s.Get(models.SettingLDAPGroupAttr, "memberOf"),
		UsernameAttr:    s.Get(models.SettingLDAPUsernameAttr, "uid"),
		DisplayNameAttr: s.Get(models.SettingLDAPDisplayNameAttr, "displayName"),
	}
}

// Service-account bind → search → user bind to verify password.
func Authenticate(cfg Config, username, password string) (*UserInfo, error) {
	if cfg.URL == "" || cfg.UserBase == "" {
		return nil, fmt.Errorf("LDAP URL and user base are required")
	}
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return nil, fmt.Errorf("username and password required")
	}

	// escape to prevent LDAP injection, which is absolutely a real thing
	escaped := escapeFilter(username)
	filter := strings.Replace(cfg.UserFilter, "%s", escaped, 1)
	if !strings.Contains(cfg.UserFilter, "%s") {
		filter = "(" + cfg.UsernameAttr + "=" + escaped + ")"
	}

	conn, err := dial(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("LDAP connect: %w", err)
	}
	defer conn.Close()

	if cfg.BindDN != "" {
		if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
			return nil, fmt.Errorf("LDAP bind (service): %w", err)
		}
	}

	attrs := []string{"dn", cfg.UsernameAttr, cfg.DisplayNameAttr, cfg.GroupAttr}
	searchRequest := ldap.NewSearchRequest(
		cfg.UserBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		filter,
		attrs,
		nil,
	)
	sr, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search: %w", err)
	}
	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("user not found")
	}
	if len(sr.Entries) > 1 {
		return nil, fmt.Errorf("multiple users matched")
	}
	entry := sr.Entries[0]
	userDN := entry.DN

	if err := conn.Bind(userDN, password); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	info := &UserInfo{DN: userDN}
	if v := entry.GetAttributeValue(cfg.UsernameAttr); v != "" {
		info.Username = v
	} else {
		info.Username = username
	}
	if v := entry.GetAttributeValue(cfg.DisplayNameAttr); v != "" {
		info.DisplayName = v
	} else {
		info.DisplayName = info.Username
	}
	info.Groups = entry.GetAttributeValues(cfg.GroupAttr)
	// AD returns full DNs for groups, just pull out the CN
	for i, g := range info.Groups {
		if cn := extractCN(g); cn != "" {
			info.Groups[i] = cn
		}
	}
	return info, nil
}

func escapeFilter(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case 0:
			b.WriteString("\\00")
		case '\\':
			b.WriteString("\\5c")
		case '*':
			b.WriteString("\\2a")
		case '(':
			b.WriteString("\\28")
		case ')':
			b.WriteString("\\29")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Pulls "Admins" out of "CN=Admins,OU=Groups,DC=example,DC=com".
func extractCN(dn string) string {
	dn = strings.TrimSpace(dn)
	if strings.HasPrefix(strings.ToUpper(dn), "CN=") {
		end := strings.Index(dn, ",")
		if end > 0 {
			return strings.TrimSpace(dn[3:end])
		}
		return strings.TrimSpace(dn[3:])
	}
	return dn
}

func dial(urlStr string) (*ldap.Conn, error) {
	if strings.HasPrefix(strings.ToLower(urlStr), "ldaps://") {
		hostPort := strings.TrimPrefix(strings.ToLower(urlStr), "ldaps://")
		return ldap.DialTLS("tcp", hostPort, &tls.Config{ServerName: strings.Split(hostPort, ":")[0], InsecureSkipVerify: false})
	}
	hostPort := strings.TrimPrefix(strings.ToLower(urlStr), "ldap://")
	return ldap.Dial("tcp", hostPort)
}

func init() {
	ldap.DefaultTimeout = 15 * time.Second
}
