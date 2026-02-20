package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func randomKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	key := randomKey(t)
	ct, err := Encrypt(key, []byte("hello world"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Decrypt(key, ct)
	if err != nil {
		t.Fatal(err)
	}
	if pt != "hello world" {
		t.Errorf("got %q, want %q", pt, "hello world")
	}
}

func TestEncryptDecrypt_EmptyString(t *testing.T) {
	key := randomKey(t)
	ct, err := Encrypt(key, []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Decrypt(key, ct)
	if err != nil {
		t.Fatal(err)
	}
	if pt != "" {
		t.Errorf("expected empty string, got %q", pt)
	}
}

func TestEncrypt_HasPrefix(t *testing.T) {
	key := randomKey(t)
	ct, err := Encrypt(key, []byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ct, EncryptedPrefix) {
		t.Errorf("ciphertext should start with %q, got %q", EncryptedPrefix, ct[:20])
	}
}

func TestDecrypt_PlaintextPassthrough(t *testing.T) {
	key := randomKey(t)
	pt, err := Decrypt(key, "some legacy value")
	if err != nil {
		t.Fatal(err)
	}
	if pt != "some legacy value" {
		t.Errorf("passthrough failed: got %q", pt)
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	keyA := randomKey(t)
	keyB := randomKey(t)

	ct, err := Encrypt(keyA, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Decrypt(keyB, ct)
	if err == nil {
		t.Fatal("decrypting with wrong key should fail")
	}
}

func TestDecrypt_CorruptedCiphertext(t *testing.T) {
	key := randomKey(t)
	ct, err := Encrypt(key, []byte("fragile"))
	if err != nil {
		t.Fatal(err)
	}

	// flip a byte in the base64 payload
	payload := strings.TrimPrefix(ct, EncryptedPrefix)
	raw, _ := base64.StdEncoding.DecodeString(payload)
	if len(raw) > 0 {
		raw[len(raw)/2] ^= 0xff
	}
	corrupted := EncryptedPrefix + base64.StdEncoding.EncodeToString(raw)

	_, err = Decrypt(key, corrupted)
	if err == nil {
		t.Fatal("corrupted ciphertext should fail")
	}
}

func TestEncryptBytes_RoundTrip(t *testing.T) {
	key := randomKey(t)
	original := []byte("binary payload \x00\x01\x02")

	ct, err := EncryptBytes(key, original)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := DecryptBytes(key, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, original) {
		t.Errorf("round-trip mismatch")
	}
}

func TestEncryptBytes_DifferentNonces(t *testing.T) {
	key := randomKey(t)
	data := []byte("same input")

	ct1, _ := EncryptBytes(key, data)
	ct2, _ := EncryptBytes(key, data)

	if bytes.Equal(ct1, ct2) {
		t.Error("two encryptions of the same data should produce different ciphertexts")
	}
}

func TestKeyProvider_32ByteKey(t *testing.T) {
	raw := strings.Repeat("A", 32)
	kp := NewKeyProviderFromRaw(raw)
	if !kp.Enabled() {
		t.Error("32-byte raw key should enable the provider")
	}
}

func TestKeyProvider_HexKey(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	raw := hex.EncodeToString(key) // 64 hex chars
	kp := NewKeyProviderFromRaw(raw)
	if !kp.Enabled() {
		t.Error("64-char hex key should enable the provider")
	}
}

func TestKeyProvider_Base64Key(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	raw := base64.StdEncoding.EncodeToString(key)
	kp := NewKeyProviderFromRaw(raw)
	if !kp.Enabled() {
		t.Error("base64-encoded 32-byte key should enable the provider")
	}
}

func TestKeyProvider_BadKey(t *testing.T) {
	kp := NewKeyProviderFromRaw("tooshort")
	if kp.Enabled() {
		t.Error("short key should not enable the provider")
	}
}
