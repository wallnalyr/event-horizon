package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/fileez/fileez/internal/secure"
	"github.com/fileez/fileez/internal/store"
)

// LockHandler handles session lock/unlock operations.
type LockHandler struct {
	session   *store.SessionManager
	files     *store.FileStore
	clipboard *store.ClipboardStore
}

// NewLockHandler creates a new lock handler.
func NewLockHandler(session *store.SessionManager, files *store.FileStore, clipboard *store.ClipboardStore) *LockHandler {
	return &LockHandler{
		session:   session,
		files:     files,
		clipboard: clipboard,
	}
}

// LockRequest is the request body for E2EE lock operations.
// Client derives key from password, encrypts data, and sends only keyHash for verification.
type LockRequest struct {
	// E2EE fields - client-side encryption
	KeyHashB64  string `json:"keyHash_b64"`  // SHA-256 hash of derived key
	SaltB64     string `json:"salt_b64"`     // PBKDF2 salt
	ClearExisting bool `json:"clearExisting"` // If true, shred all data before locking

	// Encrypted data from client (server cannot decrypt)
	EncryptedClipboardB64 string                    `json:"encryptedClipboard_b64,omitempty"`
	EncryptedImageB64     string                    `json:"encryptedImage_b64,omitempty"`
	ImageMimeType         string                    `json:"imageMimeType,omitempty"`
	EncryptedFiles        []store.EncryptedFileInfo `json:"encryptedFiles,omitempty"`
}

// UnlockRequest is the request body for E2EE unlock operations.
type UnlockRequest struct {
	KeyHashB64 string `json:"keyHash_b64"` // SHA-256 hash of derived key
}

// UnlockResponse contains encrypted data for client-side decryption.
type UnlockResponse struct {
	Token                 string                    `json:"token"`
	Locked                bool                      `json:"locked"`
	HasSession            bool                      `json:"hasSession"`
	EncryptedClipboardB64 string                    `json:"encryptedClipboard_b64,omitempty"`
	EncryptedImageB64     string                    `json:"encryptedImage_b64,omitempty"`
	ImageMimeType         string                    `json:"imageMimeType,omitempty"`
	EncryptedFiles        []store.EncryptedFileInfo `json:"encryptedFiles,omitempty"`
}

// LockStatusResponse is the response for lock status.
type LockStatusResponse struct {
	Locked     bool   `json:"locked"`
	HasSession bool   `json:"hasSession"`
	HasData    bool   `json:"hasData"`
	Token      string `json:"token,omitempty"`
}

// Status handles GET /api/lock/status
func (h *LockHandler) Status(w http.ResponseWriter, r *http.Request) {
	// Check if there's any data
	hasData := h.files.Count() > 0 || h.clipboard.HasText() || h.clipboard.HasImage()

	// Check if session exists
	session := h.session.GetSession()
	hasSession := session != nil

	resp := LockStatusResponse{
		Locked:     h.session.IsLocked(),
		HasSession: hasSession,
		HasData:    hasData,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Lock handles POST /api/lock
// E2EE: Receives encrypted blobs from client, stores keyHash for verification.
// Server cannot decrypt the data.
func (h *LockHandler) Lock(w http.ResponseWriter, r *http.Request) {
	// Parse request
	var req LockRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required E2EE fields
	if req.KeyHashB64 == "" || req.SaltB64 == "" {
		http.Error(w, "Missing keyHash or salt", http.StatusBadRequest)
		return
	}

	// Decode keyHash and salt
	keyHash, err := base64.StdEncoding.DecodeString(req.KeyHashB64)
	if err != nil || len(keyHash) != 32 { // SHA-256 = 32 bytes
		http.Error(w, "Invalid keyHash", http.StatusBadRequest)
		return
	}

	salt, err := base64.StdEncoding.DecodeString(req.SaltB64)
	if err != nil || len(salt) < 16 { // Salt must be at least 16 bytes
		http.Error(w, "Invalid salt", http.StatusBadRequest)
		return
	}

	// Handle existing data based on clearExisting flag
	if req.ClearExisting {
		// Shred all existing data before locking
		if h.files != nil {
			h.files.ShredAll()
		}
		if h.clipboard != nil {
			h.clipboard.ShredAll()
		}
	} else {
		// Store encrypted blobs from client (server cannot decrypt)
		if h.clipboard != nil {
			// Shred plaintext first
			h.clipboard.ShredAll()

			// Store encrypted clipboard text
			if req.EncryptedClipboardB64 != "" {
				encrypted, err := base64.StdEncoding.DecodeString(req.EncryptedClipboardB64)
				if err == nil {
					h.clipboard.SetEncryptedText(encrypted)
				}
			}

			// Store encrypted clipboard image
			if req.EncryptedImageB64 != "" {
				encrypted, err := base64.StdEncoding.DecodeString(req.EncryptedImageB64)
				if err == nil {
					h.clipboard.SetEncryptedImage(encrypted, req.ImageMimeType)
				}
			}
		}

		// Store encrypted files
		if h.files != nil && len(req.EncryptedFiles) > 0 {
			h.files.SetEncryptedFiles(req.EncryptedFiles)
		} else if h.files != nil {
			// No encrypted files provided, shred existing
			h.files.ShredAll()
		}
	}

	// Lock session with keyHash and salt (server cannot derive key)
	if err := h.session.Lock(keyHash, salt); err != nil {
		if err == store.ErrSessionLocked {
			http.Error(w, "Session already locked", http.StatusConflict)
			return
		}
		http.Error(w, "Failed to lock session", http.StatusInternalServerError)
		return
	}

	// Get token for client
	token := h.session.GetToken()

	resp := LockStatusResponse{
		Locked:     true,
		HasSession: true,
		Token:      token,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Unlock handles POST /api/unlock
// E2EE: Verifies keyHash and returns encrypted blobs for client-side decryption.
// IMPORTANT: Session STAYS LOCKED. Data STAYS ENCRYPTED on server.
// Client decrypts locally for display only. Each device must verify password.
func (h *LockHandler) Unlock(w http.ResponseWriter, r *http.Request) {
	// Parse request
	var req UnlockRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate keyHash
	if req.KeyHashB64 == "" {
		http.Error(w, "Missing keyHash", http.StatusBadRequest)
		return
	}

	// Decode keyHash
	keyHash, err := base64.StdEncoding.DecodeString(req.KeyHashB64)
	if err != nil || len(keyHash) != 32 { // SHA-256 = 32 bytes
		http.Error(w, "Invalid keyHash", http.StatusBadRequest)
		return
	}

	// SECURITY: Verify keyHash using constant-time comparison
	if err := h.session.VerifyKeyHash(keyHash); err != nil {
		switch err {
		case store.ErrSessionNotLocked:
			http.Error(w, "Session not locked", http.StatusConflict)
		case store.ErrInvalidPassword:
			http.Error(w, "Invalid password", http.StatusUnauthorized)
		default:
			http.Error(w, "Failed to verify password", http.StatusInternalServerError)
		}
		return
	}

	// KeyHash is correct - return encrypted blobs for client-side decryption
	// IMPORTANT: Session stays locked, data stays encrypted on server
	resp := UnlockResponse{
		Token:      h.session.GetToken(),
		Locked:     true, // Session STAYS locked
		HasSession: true,
	}

	// Get encrypted clipboard text
	if h.clipboard != nil {
		if encryptedText := h.clipboard.GetEncryptedText(); encryptedText != nil {
			resp.EncryptedClipboardB64 = base64.StdEncoding.EncodeToString(encryptedText)
		}

		// Get encrypted clipboard image
		if encryptedImage, mimeType := h.clipboard.GetEncryptedImage(); encryptedImage != nil {
			resp.EncryptedImageB64 = base64.StdEncoding.EncodeToString(encryptedImage)
			resp.ImageMimeType = mimeType
		}
	}

	// Get encrypted files
	if h.files != nil {
		resp.EncryptedFiles = h.files.GetEncryptedFiles()
	}

	// DO NOT unlock session - data stays encrypted on server
	// DO NOT clear encrypted data - it's the only copy
	// Client decrypts locally and must re-encrypt before saving

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// GetSalt handles GET /api/lock/salt
// Returns the PBKDF2 salt for client-side key derivation during unlock.
func (h *LockHandler) GetSalt(w http.ResponseWriter, r *http.Request) {
	if !h.session.IsLocked() {
		http.Error(w, "Session not locked", http.StatusBadRequest)
		return
	}

	salt := h.session.GetSalt()
	if salt == nil {
		http.Error(w, "No salt available", http.StatusInternalServerError)
		return
	}

	resp := map[string]string{
		"salt_b64": base64.StdEncoding.EncodeToString(salt),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ForceUnlock handles POST /api/lock/force-unlock
// This shreds all data and unlocks without requiring the password.
func (h *LockHandler) ForceUnlock(w http.ResponseWriter, r *http.Request) {
	// Shred callback
	shredCallback := func() {
		// Shred all files
		if h.files != nil {
			h.files.ShredAll()
		}

		// Shred clipboard
		if h.clipboard != nil {
			h.clipboard.ShredAll()
		}
	}

	// Force unlock
	if err := h.session.ForceUnlock(shredCallback); err != nil {
		if err == store.ErrSessionNotLocked {
			http.Error(w, "Session not locked", http.StatusConflict)
			return
		}
		http.Error(w, "Failed to force unlock", http.StatusInternalServerError)
		return
	}

	// Clear any remaining data using secure shredder
	shredder := secure.NewShredder(nil)
	shredder.ShredAll()

	resp := map[string]interface{}{
		"locked":   false,
		"shredded": true,
		"message":  "All data has been securely shredded",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
