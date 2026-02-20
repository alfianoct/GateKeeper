package auth

import (
	"strings"
	"testing"
)

func TestDefaultPasswordPolicy(t *testing.T) {
	p := DefaultPasswordPolicy()

	if p.MinLength != 12 {
		t.Errorf("MinLength: want 12, got %d", p.MinLength)
	}
	if !p.RequireUppercase {
		t.Error("RequireUppercase should be true")
	}
	if !p.RequireNumber {
		t.Error("RequireNumber should be true")
	}
	if !p.RequireSpecial {
		t.Error("RequireSpecial should be true")
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"TooShort", "Ab1!", false},
		{"NoUppercase", "abcdefgh1234!", false},
		{"NoDigit", "Abcdefghijklm!", false},
		{"NoSpecial", "Abcdefghijk123", false},
		{"NoLowercase", "ABCDEFGH1234!", false},
		{"Valid", "SecurePass123!", false},
	}

	// all but "Valid" should error
	tests[0].wantErr = true
	tests[1].wantErr = true
	tests[2].wantErr = true
	tests[3].wantErr = true
	tests[4].wantErr = true

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.password)
			if tt.wantErr && err == nil {
				t.Errorf("expected error for %q", tt.password)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error for %q: %v", tt.password, err)
			}
		})
	}
}

func TestValidatePasswordPolicy_MinLengthFloor(t *testing.T) {
	policy := PasswordPolicy{MinLength: 4, RequireUppercase: true, RequireNumber: true, RequireSpecial: true}

	// "Short1!" is 7 chars — under the enforced floor of 8
	err := ValidatePasswordPolicy("Short1!", policy)
	if err == nil {
		t.Fatal("policy with MinLength=4 should still enforce floor of 8")
	}
	if !strings.Contains(err.Error(), "8") {
		t.Errorf("error should mention 8, got: %v", err)
	}
}

func TestValidatePasswordPolicy_RelaxedPolicy(t *testing.T) {
	policy := PasswordPolicy{MinLength: 8}
	// all booleans default false — only length + lowercase enforced
	err := ValidatePasswordPolicy("abcdefgh", policy)
	if err != nil {
		t.Errorf("relaxed policy should accept all-lowercase 8-char: %v", err)
	}
}

func TestValidatePasswordPolicy_LongPassword(t *testing.T) {
	long := strings.Repeat("aB1!", 25) // 100 chars
	err := ValidatePassword(long)
	if err != nil {
		t.Errorf("100-char password with all requirements should pass: %v", err)
	}
}
