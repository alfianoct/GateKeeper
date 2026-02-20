package mfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"
)

const (
	secretLen     = 20 // 160-bit, standard TOTP
	codeDigits    = 6
	timeStep      = 30
	skew          = 1 // ±1 step because clock drift is inevitable
	recoveryLen   = 10
	recoveryChars = "abcdefghjkmnpqrstuvwxyz23456789" // no lookalike chars (0/O, 1/l, etc.)
)

func GenerateSecret() (string, error) {
	b := make([]byte, secretLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate TOTP secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// Returns an otpauth:// URI for QR code rendering.
func GenerateURI(secret, account, issuer string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("digits", fmt.Sprintf("%d", codeDigits))
	v.Set("period", fmt.Sprintf("%d", timeStep))

	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	return fmt.Sprintf("otpauth://totp/%s?%s", label, v.Encode())
}

// Checks a 6-digit TOTP code. Allows ±1 step because clock skew is a thing.
func ValidateCode(secret, code string) (bool, error) {
	if len(code) != codeDigits {
		return false, nil
	}

	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(
		strings.ToUpper(strings.TrimSpace(secret)),
	)
	if err != nil {
		return false, fmt.Errorf("decode TOTP secret: %w", err)
	}

	now := time.Now().Unix()
	counter := now / timeStep

	for i := -skew; i <= skew; i++ {
		expected := generateCode(key, counter+int64(i))
		if hmac.Equal([]byte(expected), []byte(code)) {
			return true, nil
		}
	}
	return false, nil
}

func generateCode(key []byte, counter int64) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(counter))

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	truncated := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	otp := truncated % uint32(math.Pow10(codeDigits))
	return fmt.Sprintf("%0*d", codeDigits, otp)
}

func GenerateRecoveryCodes() ([]string, error) {
	codes := make([]string, recoveryLen)
	for i := range codes {
		code, err := randomCode(8)
		if err != nil {
			return nil, err
		}
		codes[i] = code[:4] + "-" + code[4:]
	}
	return codes, nil
}

func randomCode(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i := range b {
		out[i] = recoveryChars[int(b[i])%len(recoveryChars)]
	}
	return string(out), nil
}
