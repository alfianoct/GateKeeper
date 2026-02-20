package mfa

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"regexp"
	"strings"
	"testing"
	"time"
)

func testGenerateCode(secret string, t int64) string {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	counter := t / 30
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(counter))
	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	truncated := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	otp := truncated % uint32(math.Pow10(6))
	return fmt.Sprintf("%06d", otp)
}

func TestGenerateSecret(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret() error: %v", err)
	}
	if secret == "" {
		t.Fatal("secret should not be empty")
	}

	// 20 bytes → 32 base32 chars (no padding)
	if len(secret) != 32 {
		t.Errorf("expected 32 base32 chars, got %d", len(secret))
	}

	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatalf("secret is not valid base32: %v", err)
	}
	if len(decoded) != 20 {
		t.Errorf("decoded length: want 20, got %d", len(decoded))
	}

	// two calls should produce different secrets
	secret2, _ := GenerateSecret()
	if secret == secret2 {
		t.Error("two consecutive secrets should differ")
	}
}

func TestGenerateURI(t *testing.T) {
	uri := GenerateURI("JBSWY3DPEHPK3PXP", "alice@example.com", "GateKeeper")

	checks := []struct {
		name   string
		substr string
	}{
		{"scheme", "otpauth://totp/"},
		{"secret param", "secret=JBSWY3DPEHPK3PXP"},
		{"issuer param", "issuer=GateKeeper"},
		{"account in label", "alice@example.com"},
	}
	for _, c := range checks {
		if !strings.Contains(uri, c.substr) {
			t.Errorf("URI missing %s (%q): %s", c.name, c.substr, uri)
		}
	}
}

func TestValidateCode_Valid(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().Unix()
	code := testGenerateCode(secret, now)

	ok, err := ValidateCode(secret, code)
	if err != nil {
		t.Fatalf("ValidateCode() error: %v", err)
	}
	if !ok {
		t.Error("expected valid code to pass")
	}
}

func TestValidateCode_WrongCode(t *testing.T) {
	secret, _ := GenerateSecret()

	ok, err := ValidateCode(secret, "000000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// theoretically could collide, but vanishingly unlikely
	if ok {
		t.Error("000000 should almost never match a random secret")
	}
}

func TestValidateCode_WrongLength(t *testing.T) {
	secret, _ := GenerateSecret()

	ok, err := ValidateCode(secret, "12345")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("5-digit code should be rejected")
	}
}

func TestValidateCode_InvalidSecret(t *testing.T) {
	_, err := ValidateCode("!!!not-base32!!!", "123456")
	if err == nil {
		t.Fatal("expected error for non-base32 secret")
	}
}

func TestGenerateRecoveryCodes(t *testing.T) {
	codes, err := GenerateRecoveryCodes()
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes() error: %v", err)
	}
	if len(codes) != 10 {
		t.Fatalf("expected 10 codes, got %d", len(codes))
	}

	pattern := regexp.MustCompile(`^[a-z2-9]{4}-[a-z2-9]{4}$`)
	seen := make(map[string]bool)

	for i, code := range codes {
		if !pattern.MatchString(code) {
			t.Errorf("code[%d] %q doesn't match XXXX-XXXX pattern", i, code)
		}
		if seen[code] {
			t.Errorf("duplicate code: %s", code)
		}
		seen[code] = true
	}
}
