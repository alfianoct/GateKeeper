package id

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// New returns 32 hex chars of crypto/rand.
func New() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Short returns 12 hex chars, used for session IDs.
func Short() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate short id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
