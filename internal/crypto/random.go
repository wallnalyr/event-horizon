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
	// NonceBytes is the standard nonce size for AES-GCM (96 bits = 12 bytes).
	NonceBytes = 12
	// SaltBytes is the standard salt size for PBKDF2 (128 bits = 16 bytes).
	SaltBytes = 16
)

var (
	// ErrRandomGeneration indicates a failure to generate random bytes.
	ErrRandomGeneration = errors.New("failed to generate cryptographically secure random bytes")
)

// RandomBytes generates cryptographically secure random bytes.
// Returns a SecureBuffer containing the random data.
// IMPORTANT: Caller must call Destroy() on the returned buffer.
func RandomBytes(size int) (*secure.SecureBuffer, error) {
	if size <= 0 {
		return nil, errors.New("size must be positive")
	}

	buf, err := secure.NewSecureBuffer(size)
	if err != nil {
		return nil, err
	}

	err = buf.MutableUse(func(data []byte) error {
		_, err := io.ReadFull(rand.Reader, data)
		return err
	})

	if err != nil {
		buf.Destroy()
		return nil, ErrRandomGeneration
	}

	return buf, nil
}

// RandomBytesRaw generates cryptographically secure random bytes.
// WARNING: The caller is responsible for zeroing the returned slice.
// Prefer RandomBytes() which returns a SecureBuffer.
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

// GenerateSessionToken generates a new random session token.
// Returns a SecureBuffer containing a 64-character hex string (256 bits of entropy).
// IMPORTANT: Caller must call Destroy() on the returned buffer.
func GenerateSessionToken() (*secure.SecureBuffer, error) {
	data, err := RandomBytesRaw(SessionTokenBytes)
	if err != nil {
		return nil, err
	}

	// Encode to hex
	tokenHex := hex.EncodeToString(data)
	// Zero the raw bytes
	secure.Shred(data)

	// Create secure buffer from hex string
	return secure.NewSecureBufferFromBytes([]byte(tokenHex))
}

// GenerateSessionTokenString generates a session token as a string.
// WARNING: Strings are immutable in Go and cannot be securely zeroed.
// Use GenerateSessionToken() for sensitive contexts.
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

// GenerateNonce generates a random nonce for AES-GCM.
// Returns a SecureBuffer containing 12 bytes.
// IMPORTANT: Caller must call Destroy() on the returned buffer.
func GenerateNonce() (*secure.SecureBuffer, error) {
	return RandomBytes(NonceBytes)
}

// GenerateSalt generates a random salt for key derivation.
// Returns a SecureBuffer containing 16 bytes.
// IMPORTANT: Caller must call Destroy() on the returned buffer.
func GenerateSalt() (*secure.SecureBuffer, error) {
	return RandomBytes(SaltBytes)
}

// GenerateSaltRaw generates a random salt as raw bytes.
// WARNING: Caller must zero the returned slice when done.
func GenerateSaltRaw() ([]byte, error) {
	return RandomBytesRaw(SaltBytes)
}

// ConstantTimeCompare compares two byte slices in constant time.
// Returns true if slices are equal, false otherwise.
// Prevents timing attacks when comparing secrets like keyHash.
func ConstantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
