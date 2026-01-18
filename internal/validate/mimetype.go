package validate

import (
	"errors"
	"strings"
)

var (
	// ErrMIMETypeInvalid indicates an invalid or disallowed MIME type.
	ErrMIMETypeInvalid = errors.New("invalid or disallowed MIME type")
	// ErrMIMETypeEmpty indicates an empty MIME type.
	ErrMIMETypeEmpty = errors.New("MIME type cannot be empty")
)

// AllowedMIMETypes is the allowlist of permitted MIME types.
// This prevents upload of potentially dangerous file types.
var AllowedMIMETypes = map[string]bool{
	// Documents
	"application/pdf":                                                        true,
	"application/msword":                                                     true,
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document": true,
	"application/vnd.ms-excel":                                                true,
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":       true,
	"application/vnd.ms-powerpoint":                                           true,
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": true,
	"application/rtf":       true,
	"application/epub+zip":  true,
	"application/x-mobipocket-ebook": true,

	// Text
	"text/plain":      true,
	"text/html":       true,
	"text/css":        true,
	"text/javascript": true,
	"text/csv":        true,
	"text/xml":        true,
	"text/markdown":   true,
	"text/x-python":   true,
	"text/x-java":     true,
	"text/x-c":        true,
	"text/x-c++":      true,
	"text/x-go":       true,
	"text/x-rust":     true,

	// Images
	"image/jpeg":    true,
	"image/png":     true,
	"image/gif":     true,
	"image/webp":    true,
	"image/svg+xml": true,
	"image/bmp":     true,
	"image/tiff":    true,
	"image/x-icon":  true,
	"image/heic":    true,
	"image/heif":    true,
	"image/avif":    true,

	// Audio
	"audio/mpeg":      true,
	"audio/mp3":       true,
	"audio/wav":       true,
	"audio/ogg":       true,
	"audio/flac":      true,
	"audio/aac":       true,
	"audio/webm":      true,
	"audio/x-m4a":     true,
	"audio/mp4":       true,

	// Video
	"video/mp4":       true,
	"video/webm":      true,
	"video/ogg":       true,
	"video/x-msvideo": true,
	"video/quicktime": true,
	"video/x-matroska": true,
	"video/x-flv":     true,

	// Archives (non-executable)
	"application/zip":              true,
	"application/x-rar-compressed": true,
	"application/x-7z-compressed":  true,
	"application/gzip":             true,
	"application/x-tar":            true,
	"application/x-bzip2":          true,

	// Data formats
	"application/json":            true,
	"application/xml":             true,
	"application/x-yaml":          true,
	"application/toml":            true,

	// Fonts
	"font/ttf":   true,
	"font/otf":   true,
	"font/woff":  true,
	"font/woff2": true,

	// Generic binary (fallback)
	"application/octet-stream": true,
}

// BlockedMIMETypes are types that are explicitly blocked even if they match a category.
var BlockedMIMETypes = map[string]bool{
	// Executables
	"application/x-executable":      true,
	"application/x-msdos-program":   true,
	"application/x-msdownload":      true,
	"application/x-sh":              true,
	"application/x-shellscript":     true,
	"application/x-bat":             true,
	"application/x-msi":             true,
	"application/vnd.microsoft.portable-executable": true,
	"application/x-dosexec":         true,

	// Scripts that could be executed
	"application/x-perl":       true,
	"application/x-ruby":       true,
	"application/x-php":        true,

	// Java
	"application/java-archive": true,
	"application/x-java-class": true,

	// macOS
	"application/x-apple-diskimage": true,
}

// MIMEType validates a MIME type against the allowlist.
// Returns the normalized MIME type or an error.
func MIMEType(mimeType string) (string, error) {
	mimeType = strings.TrimSpace(mimeType)

	if mimeType == "" {
		return "", ErrMIMETypeEmpty
	}

	// Normalize: lowercase, remove parameters
	mimeType = strings.ToLower(mimeType)
	if idx := strings.Index(mimeType, ";"); idx > 0 {
		mimeType = strings.TrimSpace(mimeType[:idx])
	}

	// Check blocklist first
	if BlockedMIMETypes[mimeType] {
		return "", ErrMIMETypeInvalid
	}

	// Check allowlist
	if !AllowedMIMETypes[mimeType] {
		// Check if it's a text type (allow text/*)
		if strings.HasPrefix(mimeType, "text/") {
			return mimeType, nil
		}
		return "", ErrMIMETypeInvalid
	}

	return mimeType, nil
}

// MIMETypeOrDefault validates a MIME type, returning a default if invalid.
// This is useful when you want to accept any file but normalize the type.
func MIMETypeOrDefault(mimeType, defaultType string) string {
	validated, err := MIMEType(mimeType)
	if err != nil {
		return defaultType
	}
	return validated
}

// IsMIMETypeAllowed checks if a MIME type is allowed without returning the normalized value.
func IsMIMETypeAllowed(mimeType string) bool {
	_, err := MIMEType(mimeType)
	return err == nil
}

// IsImageMIMEType checks if the MIME type is an image type.
func IsImageMIMEType(mimeType string) bool {
	mimeType = strings.ToLower(strings.TrimSpace(mimeType))
	if idx := strings.Index(mimeType, ";"); idx > 0 {
		mimeType = strings.TrimSpace(mimeType[:idx])
	}
	return strings.HasPrefix(mimeType, "image/")
}
