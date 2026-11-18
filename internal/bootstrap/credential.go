package bootstrap

import (
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/sergeymakinen/go-crypt/sha512"
)

const passwordValidationMessage = "Пароли должны совпадать: минимум 16 символов, максимум 1024 байта UTF-8, без NUL и переводов строк."

// ValidatePassword checks the fresh Entware root credential before hashing.
func ValidatePassword(password, repeat string) error {
	if password != repeat || !utf8.ValidString(password) || len(password) > 1024 || utf8.RuneCountInString(password) < 16 || strings.ContainsAny(password, "\x00\r\n") {
		return errors.New(passwordValidationMessage)
	}
	return nil
}

// NewPasswordHash creates a crypt(3) hash without retaining the plaintext.
func NewPasswordHash(password, repeat string) (string, error) {
	if err := ValidatePassword(password, repeat); err != nil {
		return "", err
	}
	hash, err := sha512.NewHash(password, 100000)
	if err != nil {
		return "", errors.New("Не удалось подготовить пароль Entware. Повторите попытку.")
	}
	return hash, nil
}
