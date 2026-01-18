package validate

import (
	"errors"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

var (
	// ErrFilenameEmpty indicates an empty filename.
	ErrFilenameEmpty = errors.New("filename cannot be empty")
	// ErrFilenameTooLong indicates the filename exceeds the maximum length.
	ErrFilenameTooLong = errors.New("filename too long")
	// ErrFilenameInvalid indicates the filename contains invalid characters.
	ErrFilenameInvalid = errors.New("filename contains invalid characters")
	// ErrFilenamePathTraversal indicates a path traversal attempt.
	ErrFilenamePathTraversal = errors.New("filename contains path traversal")

	// dangerousPatterns are patterns that could be dangerous in filenames
	dangerousPatterns = regexp.MustCompile(`[<>:"|?*\x00-\x1f]`)

	// reservedNames are Windows reserved filenames (case insensitive)
	reservedNames = map[string]bool{
		"CON": true, "PRN": true, "AUX": true, "NUL": true,
		"COM1": true, "COM2": true, "COM3": true, "COM4": true,
		"COM5": true, "COM6": true, "COM7": true, "COM8": true, "COM9": true,
		"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true,
		"LPT5": true, "LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
	}
)

// Filename validates and sanitizes a filename.
// This prevents path traversal attacks and removes dangerous characters.
// Returns the sanitized filename or an error.
func Filename(name string) (string, error) {
	// Trim whitespace
	name = strings.TrimSpace(name)

	if name == "" {
		return "", ErrFilenameEmpty
	}

	// Check length before sanitization
	if len(name) > MaxFilenameLength {
		return "", ErrFilenameTooLong
	}

	// Detect path traversal attempts
	if strings.Contains(name, "..") {
		return "", ErrFilenamePathTraversal
	}

	// Remove any directory components (extract base name)
	name = filepath.Base(name)

	// After Base(), check again for path traversal
	if name == "." || name == ".." {
		return "", ErrFilenamePathTraversal
	}

	// Remove dangerous characters
	name = dangerousPatterns.ReplaceAllString(name, "_")

	// Remove leading/trailing dots and spaces (Windows issue)
	name = strings.Trim(name, ". ")

	// Check for empty after sanitization
	if name == "" {
		return "", ErrFilenameInvalid
	}

	// Check for Windows reserved names
	baseName := strings.ToUpper(name)
	// Remove extension for check
	if idx := strings.Index(baseName, "."); idx > 0 {
		baseName = baseName[:idx]
	}
	if reservedNames[baseName] {
		// Prefix with underscore to make safe
		name = "_" + name
	}

	// Final length check after sanitization
	if len(name) > MaxFilenameLength {
		// Truncate, preserving extension if possible
		ext := filepath.Ext(name)
		if len(ext) < MaxFilenameLength-10 {
			name = name[:MaxFilenameLength-len(ext)] + ext
		} else {
			name = name[:MaxFilenameLength]
		}
	}

	return name, nil
}

// FilenameStrict is like Filename but rejects any filename requiring sanitization.
// Use this when you want to inform users their filename is invalid rather than
// silently modifying it.
func FilenameStrict(name string) (string, error) {
	name = strings.TrimSpace(name)

	if name == "" {
		return "", ErrFilenameEmpty
	}

	if len(name) > MaxFilenameLength {
		return "", ErrFilenameTooLong
	}

	// Check for path separators
	if strings.ContainsAny(name, "/\\") {
		return "", ErrFilenamePathTraversal
	}

	// Check for path traversal
	if strings.Contains(name, "..") {
		return "", ErrFilenamePathTraversal
	}

	// Check for dangerous characters
	if dangerousPatterns.MatchString(name) {
		return "", ErrFilenameInvalid
	}

	// Check for leading/trailing dots
	if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") {
		return "", ErrFilenameInvalid
	}

	// Check for control characters
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", ErrFilenameInvalid
		}
	}

	// Check for Windows reserved names
	baseName := strings.ToUpper(name)
	if idx := strings.Index(baseName, "."); idx > 0 {
		baseName = baseName[:idx]
	}
	if reservedNames[baseName] {
		return "", ErrFilenameInvalid
	}

	return name, nil
}

// SanitizeFilename is an alias for Filename.
// Deprecated: Use Filename instead.
func SanitizeFilename(name string) (string, error) {
	return Filename(name)
}
