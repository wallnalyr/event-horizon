// Package crypto provides cryptographic primitives using secure memory.
package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"

	"github.com/fileez/fileez/internal/secure"
)

const (
	// FileIDBytes is the number of bytes in a file ID (64 bits = 8 bytes = 16 hex chars).
	FileIDBytes = 8
	// SessionTokenBytes is the number of bytes in a session token (256 bits = 32 bytes = 64 hex chars).
	SessionTokenBytes = 32
)

var (
	// ErrRandomGeneration indicates a failure to generate random bytes.
	ErrRandomGeneration = errors.New("failed to generate cryptographically secure random bytes")
)

// RandomBytesRaw generates cryptographically secure random bytes.
// WARNING: The caller is responsible for zeroing the returned slice.
func RandomBytesRaw(size int) ([]byte, error) {
	if size <= 0 {
		return nil, errors.New("size must be positive")
	}

	data := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		return nil, ErrRandomGeneration
	}

	return data, nil
}

// GenerateFileID generates a new random file ID.
// Returns a 16-character hex string (64 bits of entropy).
func GenerateFileID() (string, error) {
	data, err := RandomBytesRaw(FileIDBytes)
	if err != nil {
		return "", err
	}
	id := hex.EncodeToString(data)
	// Zero the raw bytes
	secure.Shred(data)
	return id, nil
}

// GenerateSessionTokenString generates a session token as a string.
// WARNING: Strings are immutable in Go and cannot be securely zeroed.
func GenerateSessionTokenString() (string, error) {
	data, err := RandomBytesRaw(SessionTokenBytes)
	if err != nil {
		return "", err
	}
	token := hex.EncodeToString(data)
	// Zero the raw bytes
	secure.Shred(data)
	return token, nil
}

// ConstantTimeCompare compares two byte slices in constant time.
// Returns true if slices are equal, false otherwise.
// Prevents timing attacks when comparing secrets like keyHash.
func ConstantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
