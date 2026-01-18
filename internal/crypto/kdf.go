package crypto

import (
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/pbkdf2"

	"github.com/fileez/fileez/internal/secure"
)

const (
	// PBKDF2Iterations is the number of iterations for PBKDF2.
	// OWASP 2024 recommendation for PBKDF2-SHA256.
	PBKDF2Iterations = 600000

	// AES256KeySize is the key size for AES-256 (32 bytes).
	AES256KeySize = 32
)

var (
	// ErrPasswordEmpty indicates an empty password was provided.
	ErrPasswordEmpty = errors.New("password cannot be empty")
	// ErrSaltInvalid indicates an invalid salt was provided.
	ErrSaltInvalid = errors.New("salt must be at least 16 bytes")
)

// DeriveKey derives an encryption key from a password using PBKDF2-SHA256.
// Uses 600,000 iterations per OWASP 2024 recommendations.
//
// Parameters:
//   - password: SecureBuffer containing the password
//   - salt: Salt bytes (must be at least 16 bytes, ideally random)
//
// Returns a SecureKey that is encrypted in memory.
// IMPORTANT: Caller must call Destroy() on the returned key.
func DeriveKey(password *secure.SecureBuffer, salt []byte) (*secure.SecureKey, error) {
	if password == nil || password.Size() == 0 {
		return nil, ErrPasswordEmpty
	}
	if len(salt) < SaltBytes {
		return nil, ErrSaltInvalid
	}

	var derivedKey []byte

	err := password.Use(func(passwordBytes []byte) error {
		// Derive key using PBKDF2-SHA256
		derivedKey = pbkdf2.Key(passwordBytes, salt, PBKDF2Iterations, AES256KeySize, sha256.New)
		return nil
	})

	if err != nil {
		return nil, err
	}

	// Create SecureKey from derived key (encrypts in memory)
	key, err := secure.NewSecureKey(derivedKey)

	// Immediately shred the intermediate key bytes
	secure.Shred(derivedKey)

	if err != nil {
		return nil, err
	}

	return key, nil
}

// DeriveKeyFromBytes derives an encryption key from raw password bytes.
// WARNING: The passwordBytes will be zeroed after use.
// Prefer DeriveKey() which uses SecureBuffer.
func DeriveKeyFromBytes(passwordBytes, salt []byte) (*secure.SecureKey, error) {
	if len(passwordBytes) == 0 {
		return nil, ErrPasswordEmpty
	}
	if len(salt) < SaltBytes {
		return nil, ErrSaltInvalid
	}

	// Derive key using PBKDF2-SHA256
	derivedKey := pbkdf2.Key(passwordBytes, salt, PBKDF2Iterations, AES256KeySize, sha256.New)

	// Zero the password bytes
	secure.Shred(passwordBytes)

	// Create SecureKey from derived key
	key, err := secure.NewSecureKey(derivedKey)

	// Shred the derived key
	secure.Shred(derivedKey)

	if err != nil {
		return nil, err
	}

	return key, nil
}

// DeriveKeyWithIterations derives a key with a custom iteration count.
// WARNING: Do not use fewer than 600,000 iterations for PBKDF2-SHA256.
// This function exists for testing and compatibility purposes only.
func DeriveKeyWithIterations(password *secure.SecureBuffer, salt []byte, iterations int) (*secure.SecureKey, error) {
	if password == nil || password.Size() == 0 {
		return nil, ErrPasswordEmpty
	}
	if len(salt) < SaltBytes {
		return nil, ErrSaltInvalid
	}
	if iterations < 1 {
		return nil, errors.New("iterations must be positive")
	}

	var derivedKey []byte

	err := password.Use(func(passwordBytes []byte) error {
		derivedKey = pbkdf2.Key(passwordBytes, salt, iterations, AES256KeySize, sha256.New)
		return nil
	})

	if err != nil {
		return nil, err
	}

	key, err := secure.NewSecureKey(derivedKey)
	secure.Shred(derivedKey)

	if err != nil {
		return nil, err
	}

	return key, nil
}
