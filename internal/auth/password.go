package auth

import (
	"fmt"
	"strings"
	"unicode"
)

type PasswordPolicy struct {
	MinLength        int
	RequireUppercase bool
	RequireNumber    bool
	RequireSpecial   bool
}

// Hard-coded defaults for when no DB settings exist yet.
func DefaultPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{
		MinLength:        12,
		RequireUppercase: true,
		RequireNumber:    true,
		RequireSpecial:   true,
	}
}

// Backward compat wrapper — new callers should use ValidatePasswordPolicy.
func ValidatePassword(password string) error {
	return ValidatePasswordPolicy(password, DefaultPasswordPolicy())
}

func ValidatePasswordPolicy(password string, p PasswordPolicy) error {
	minLen := p.MinLength
	if minLen < 8 {
		minLen = 8
	}

	if len(password) < minLen {
		return fmt.Errorf("password must be at least %d characters", minLen)
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasDigit = true
		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
			hasSpecial = true
		}
	}

	var missing []string
	if p.RequireUppercase && !hasUpper {
		missing = append(missing, "uppercase letter")
	}
	if !hasLower {
		missing = append(missing, "lowercase letter")
	}
	if p.RequireNumber && !hasDigit {
		missing = append(missing, "digit")
	}
	if p.RequireSpecial && !hasSpecial {
		missing = append(missing, "special character")
	}

	if len(missing) > 0 {
		return fmt.Errorf("password must contain at least one %s", strings.Join(missing, ", "))
	}
	return nil
}
