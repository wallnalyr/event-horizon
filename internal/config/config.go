// Package config provides environment-based configuration.
package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds all application configuration.
type Config struct {
	// Server settings
	Port            int
	Host            string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	ShutdownTimeout time.Duration

	// Security settings
	MaxFileSize        int64         // Maximum file size in bytes
	MaxMemory          int64         // Maximum secure memory in bytes
	FileExpiry         time.Duration // Time until files auto-expire
	ClipboardExpiry    time.Duration // Time until clipboard auto-expires
	RateLimit          int           // Requests per minute (general)
	UploadRateLimit    int           // Requests per minute (uploads)
	EnableCORS         bool          // Enable CORS headers
	AllowedOrigins     []string      // CORS allowed origins

	// Feature flags
	EnableClipboard      bool
	EnableClipboardImage bool
	EnableFileSharing    bool

	// Frontend
	FrontendDir string // Directory containing built frontend files
}

// DefaultConfig returns configuration with secure defaults.
func DefaultConfig() *Config {
	return &Config{
		// Server
		Port:            3001,
		Host:            "0.0.0.0",
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    60 * time.Second, // Longer for file uploads
		ShutdownTimeout: 30 * time.Second,

		// Security
		MaxFileSize:      100 * 1024 * 1024, // 100MB
		MaxMemory:        512 * 1024 * 1024, // 512MB
		FileExpiry:       24 * time.Hour,
		ClipboardExpiry:  1 * time.Hour,
		RateLimit:        600,  // 600/min = 10/sec
		UploadRateLimit:  20,   // 20/min
		EnableCORS:       true,
		AllowedOrigins:   []string{"*"}, // Restricted in production

		// Features
		EnableClipboard:      true,
		EnableClipboardImage: true,
		EnableFileSharing:    true,

		// Frontend
		FrontendDir: "./frontend/dist",
	}
}

// LoadFromEnv loads configuration from environment variables.
// Missing variables use defaults from DefaultConfig.
func LoadFromEnv() *Config {
	cfg := DefaultConfig()

	// Server settings
	if v := os.Getenv("PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil && port > 0 && port < 65536 {
			cfg.Port = port
		}
	}

	if v := os.Getenv("HOST"); v != "" {
		cfg.Host = v
	}

	if v := os.Getenv("READ_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.ReadTimeout = d
		}
	}

	if v := os.Getenv("WRITE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.WriteTimeout = d
		}
	}

	if v := os.Getenv("SHUTDOWN_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.ShutdownTimeout = d
		}
	}

	// Security settings
	if v := os.Getenv("MAX_FILE_SIZE"); v != "" {
		if size, err := strconv.ParseInt(v, 10, 64); err == nil && size > 0 {
			cfg.MaxFileSize = size
		}
	}

	if v := os.Getenv("MAX_MEMORY"); v != "" {
		if size, err := strconv.ParseInt(v, 10, 64); err == nil && size > 0 {
			cfg.MaxMemory = size
		}
	}

	if v := os.Getenv("FILE_EXPIRY"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.FileExpiry = d
		}
	}

	if v := os.Getenv("CLIPBOARD_EXPIRY"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.ClipboardExpiry = d
		}
	}

	if v := os.Getenv("RATE_LIMIT"); v != "" {
		if limit, err := strconv.Atoi(v); err == nil && limit > 0 {
			cfg.RateLimit = limit
		}
	}

	if v := os.Getenv("UPLOAD_RATE_LIMIT"); v != "" {
		if limit, err := strconv.Atoi(v); err == nil && limit > 0 {
			cfg.UploadRateLimit = limit
		}
	}

	if v := os.Getenv("ENABLE_CORS"); v != "" {
		cfg.EnableCORS = v == "true" || v == "1" || v == "yes"
	}

	if v := os.Getenv("ALLOWED_ORIGINS"); v != "" {
		cfg.AllowedOrigins = []string{v}
	}

	// Feature flags
	if v := os.Getenv("ENABLE_CLIPBOARD"); v != "" {
		cfg.EnableClipboard = v == "true" || v == "1" || v == "yes"
	}

	if v := os.Getenv("ENABLE_CLIPBOARD_IMAGE"); v != "" {
		cfg.EnableClipboardImage = v == "true" || v == "1" || v == "yes"
	}

	if v := os.Getenv("ENABLE_FILE_SHARING"); v != "" {
		cfg.EnableFileSharing = v == "true" || v == "1" || v == "yes"
	}

	// Frontend
	if v := os.Getenv("FRONTEND_DIR"); v != "" {
		cfg.FrontendDir = v
	}

	return cfg
}

// Addr returns the listen address in host:port format.
func (c *Config) Addr() string {
	return c.Host + ":" + strconv.Itoa(c.Port)
}
