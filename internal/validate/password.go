package validate

import (
	"encoding/base64"
	"errors"

	"github.com/fileez/fileez/internal/secure"
)

const (
	// MinPasswordLength is the minimum password length.
	MinPasswordLength = 1
	// MaxPasswordLength is the maximum password length (before base64 encoding).
	MaxPasswordLength = 1024
	// MaxBase64PasswordLength is the maximum base64-encoded password length.
	// base64 expands by ~4/3, plus padding
	MaxBase64PasswordLength = (MaxPasswordLength * 4 / 3) + 4
)

var (
	// ErrPasswordTooShort indicates the password is too short.
	ErrPasswordTooShort = errors.New("password too short")
	// ErrPasswordTooLong indicates the password is too long.
	ErrPasswordTooLong = errors.New("password too long")
	// ErrPasswordInvalid indicates invalid password encoding.
	ErrPasswordInvalid = errors.New("invalid password encoding")
)

// PasswordFromBase64 decodes a base64-encoded password into a SecureBuffer.
// Passwords are sent as base64 to avoid string handling issues with special characters.
//
// IMPORTANT: Caller must call Destroy() on the returned buffer.
//
// The function:
// 1. Validates the base64 encoding
// 2. Decodes into a SecureBuffer (memory-locked)
// 3. Validates password length
// 4. Returns the secure password buffer
func PasswordFromBase64(encodedPassword string) (*secure.SecureBuffer, error) {
	if encodedPassword == "" {
		return nil, ErrPasswordTooShort
	}

	// Check max encoded length to prevent DoS
	if len(encodedPassword) > MaxBase64PasswordLength {
		return nil, ErrPasswordTooLong
	}

	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(encodedPassword)
	if err != nil {
		return nil, ErrPasswordInvalid
	}

	// Check decoded length
	if len(decoded) < MinPasswordLength {
		secure.Shred(decoded)
		return nil, ErrPasswordTooShort
	}

	if len(decoded) > MaxPasswordLength {
		secure.Shred(decoded)
		return nil, ErrPasswordTooLong
	}

	// Create SecureBuffer from decoded password
	buf, err := secure.NewSecureBufferFromBytes(decoded)

	// Shred the intermediate bytes
	secure.Shred(decoded)

	if err != nil {
		return nil, err
	}

	return buf, nil
}

// PasswordFromBase64URL decodes a URL-safe base64-encoded password.
// Use this for passwords passed in URL parameters or headers.
func PasswordFromBase64URL(encodedPassword string) (*secure.SecureBuffer, error) {
	if encodedPassword == "" {
		return nil, ErrPasswordTooShort
	}

	if len(encodedPassword) > MaxBase64PasswordLength {
		return nil, ErrPasswordTooLong
	}

	// Decode URL-safe base64
	decoded, err := base64.URLEncoding.DecodeString(encodedPassword)
	if err != nil {
		// Try without padding
		decoded, err = base64.RawURLEncoding.DecodeString(encodedPassword)
		if err != nil {
			return nil, ErrPasswordInvalid
		}
	}

	if len(decoded) < MinPasswordLength {
		secure.Shred(decoded)
		return nil, ErrPasswordTooShort
	}

	if len(decoded) > MaxPasswordLength {
		secure.Shred(decoded)
		return nil, ErrPasswordTooLong
	}

	buf, err := secure.NewSecureBufferFromBytes(decoded)
	secure.Shred(decoded)

	if err != nil {
		return nil, err
	}

	return buf, nil
}

// ValidatePasswordStrength performs basic password strength validation.
// This is optional and can be used when setting up a new lock.
// Returns nil if the password meets minimum requirements.
func ValidatePasswordStrength(password *secure.SecureBuffer) error {
	if password == nil || password.IsDestroyed() {
		return secure.ErrBufferDestroyed
	}

	size := password.Size()
	if size < MinPasswordLength {
		return ErrPasswordTooShort
	}

	if size > MaxPasswordLength {
		return ErrPasswordTooLong
	}

	return nil
}
