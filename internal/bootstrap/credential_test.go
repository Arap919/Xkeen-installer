package bootstrap

import (
	"regexp"
	"strings"
	"testing"

	"github.com/sergeymakinen/go-crypt/sha512"
)

func TestValidatePasswordBoundaries(t *testing.T) {
	valid := []string{strings.Repeat("a", 16), strings.Repeat("я", 16), strings.Repeat("😀", 16), strings.Repeat("a", 1024), strings.Repeat("😀", 256)}
	for _, password := range valid {
		if err := ValidatePassword(password, password); err != nil {
			t.Fatal("valid boundary rejected")
		}
	}
	invalid := []string{"", "keenetic", strings.Repeat("a", 15), strings.Repeat("😀", 15), strings.Repeat("a", 1025), strings.Repeat("😀", 257), strings.Repeat("a", 16) + "\x00", strings.Repeat("a", 16) + "\r", strings.Repeat("a", 16) + "\n", strings.Repeat("a", 16) + string([]byte{0xff})}
	for _, password := range invalid {
		if err := ValidatePassword(password, password); err == nil {
			t.Fatal("invalid password accepted")
		} else if strings.Contains(err.Error(), password) && password != "" {
			t.Fatal("password leaked")
		}
		if hash, err := NewPasswordHash(password, password); err == nil || hash != "" {
			t.Fatal("invalid password hashed")
		}
	}
	if err := ValidatePassword(valid[0], valid[0]+"x"); err == nil {
		t.Fatal("mismatched repeat accepted")
	}
}
func TestPasswordHashRandomSaltAndFormat(t *testing.T) {
	password := "fixture-password-only"
	first, err := NewPasswordHash(password, password)
	if err != nil {
		t.Fatal("hash failed")
	}
	second, err := NewPasswordHash(password, password)
	if err != nil {
		t.Fatal("hash failed")
	}
	if sha512.Check(first, password) != nil || sha512.Check(first, password+"x") == nil {
		t.Fatal("hash does not authenticate intended password exclusively")
	}
	pattern := regexp.MustCompile(`^\$6\$rounds=100000\$[./0-9A-Za-z]{16}\$[./0-9A-Za-z]{86}$`)
	if !pattern.MatchString(first) || !pattern.MatchString(second) || first == second || strings.Contains(first, password) {
		t.Fatal("invalid hash format or reused salt")
	}
}
