// Package validate provides input validation for all user-provided data.
// All input must be validated before use to prevent injection attacks.
package validate

import (
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
)

const (
	// FileIDLength is the expected length of a file ID in hex characters.
	FileIDLength = 16
	// SessionTokenLength is the expected length of a session token in hex characters.
	SessionTokenLength = 64
	// MaxClipboardSize is the maximum size of clipboard content (1MB).
	MaxClipboardSize = 1 * 1024 * 1024
	// MaxFilenameLength is the maximum allowed filename length.
	MaxFilenameLength = 255
)

var (
	// ErrInvalidFileID indicates an invalid file ID format.
	ErrInvalidFileID = errors.New("invalid file ID: must be 16 hex characters")
	// ErrInvalidSessionToken indicates an invalid session token format.
	ErrInvalidSessionToken = errors.New("invalid session token: must be 64 hex characters")
	// ErrClipboardTooLarge indicates the clipboard content exceeds the size limit.
	ErrClipboardTooLarge = errors.New("clipboard content too large")
	// ErrEmptyInput indicates empty input where content is required.
	ErrEmptyInput = errors.New("input cannot be empty")

	// hexPattern matches valid hex strings
	hexPattern = regexp.MustCompile(`^[a-fA-F0-9]+$`)
)

// FileID validates and normalizes a file ID.
// File IDs must be exactly 16 hex characters (64 bits).
// Returns the lowercase normalized ID or an error.
func FileID(id string) (string, error) {
	id = strings.TrimSpace(id)

	if len(id) != FileIDLength {
		return "", ErrInvalidFileID
	}

	if !hexPattern.MatchString(id) {
		return "", ErrInvalidFileID
	}

	// Verify it's valid hex by decoding
	if _, err := hex.DecodeString(id); err != nil {
		return "", ErrInvalidFileID
	}

	return strings.ToLower(id), nil
}

// SessionToken validates a session token.
// Session tokens must be exactly 64 hex characters (256 bits).
// Returns the lowercase normalized token or an error.
func SessionToken(token string) (string, error) {
	token = strings.TrimSpace(token)

	if len(token) != SessionTokenLength {
		return "", ErrInvalidSessionToken
	}

	if !hexPattern.MatchString(token) {
		return "", ErrInvalidSessionToken
	}

	// Verify it's valid hex by decoding
	if _, err := hex.DecodeString(token); err != nil {
		return "", ErrInvalidSessionToken
	}

	return strings.ToLower(token), nil
}

// ClipboardContent validates clipboard text content.
// Content must not exceed MaxClipboardSize.
// Returns the content (trimmed of leading/trailing whitespace) or an error.
func ClipboardContent(content string) (string, error) {
	if len(content) > MaxClipboardSize {
		return "", ErrClipboardTooLarge
	}

	// Trim excessive whitespace but preserve internal formatting
	content = strings.TrimSpace(content)

	return content, nil
}

// ClipboardBytes validates clipboard binary content.
// Content must not exceed MaxClipboardSize.
func ClipboardBytes(content []byte) error {
	if len(content) > MaxClipboardSize {
		return ErrClipboardTooLarge
	}
	return nil
}

// NonEmpty validates that a string is not empty after trimming.
func NonEmpty(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ErrEmptyInput
	}
	return s, nil
}

// MaxLength validates that a string does not exceed the given length.
func MaxLength(s string, maxLen int) error {
	if len(s) > maxLen {
		return errors.New("input exceeds maximum length")
	}
	return nil
}
