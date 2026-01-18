package api

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"github.com/fileez/fileez/internal/store"
	"github.com/fileez/fileez/internal/validate"
)

// decodeBase64 decodes a base64 string to bytes.
func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// ClipboardHandler handles clipboard operations.
type ClipboardHandler struct {
	clipboard *store.ClipboardStore
	session   *store.SessionManager
}

// NewClipboardHandler creates a new clipboard handler.
func NewClipboardHandler(clipboard *store.ClipboardStore, session *store.SessionManager) *ClipboardHandler {
	return &ClipboardHandler{
		clipboard: clipboard,
		session:   session,
	}
}

// ClipboardTextRequest is the request body for setting text clipboard.
// When session is locked, client sends encrypted_b64 instead of text.
type ClipboardTextRequest struct {
	Text         string `json:"text,omitempty"`
	EncryptedB64 string `json:"encrypted_b64,omitempty"` // E2EE: encrypted text when locked
}

// ClipboardTextResponse is the response for text clipboard.
type ClipboardTextResponse struct {
	Text         string `json:"text,omitempty"`
	EncryptedB64 string `json:"encrypted_b64,omitempty"` // E2EE: encrypted text when locked
	HasContent   bool   `json:"has_content"`
	Size         int    `json:"size,omitempty"`
}

// GetText handles GET /api/clipboard
// E2EE: When session is locked, returns encrypted_b64 instead of text.
func (h *ClipboardHandler) GetText(w http.ResponseWriter, r *http.Request) {
	// E2EE: If session is locked, return encrypted data for client-side decryption
	if h.session.IsLocked() {
		encrypted := h.clipboard.GetEncryptedText()
		if encrypted == nil {
			resp := ClipboardTextResponse{HasContent: false}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				log.Printf("Failed to encode clipboard response: %v", err)
			}
			return
		}

		resp := ClipboardTextResponse{
			EncryptedB64: base64.StdEncoding.EncodeToString(encrypted),
			HasContent:   true,
			Size:         len(encrypted),
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("Failed to encode clipboard response: %v", err)
		}
		return
	}

	// Normal plaintext mode
	content, err := h.clipboard.GetText()
	if err != nil {
		if err == store.ErrClipboardEmpty || err == store.ErrClipboardExpired {
			resp := ClipboardTextResponse{HasContent: false}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				log.Printf("Failed to encode clipboard response: %v", err)
			}
			return
		}
		http.Error(w, "Failed to get clipboard", http.StatusInternalServerError)
		return
	}

	resp := ClipboardTextResponse{
		Text:       string(content),
		HasContent: true,
		Size:       len(content),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Failed to encode clipboard response: %v", err)
	}
}

// SetText handles POST /api/clipboard
// E2EE: When session is locked, accepts encrypted_b64 instead of text.
// Client encrypts locally, sends ciphertext. Server stores without decrypting.
func (h *ClipboardHandler) SetText(w http.ResponseWriter, r *http.Request) {
	var req ClipboardTextRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var content []byte
	var size int

	// E2EE: If session is locked and encrypted data provided, store as encrypted
	if h.session.IsLocked() && req.EncryptedB64 != "" {
		// Decode encrypted data
		encrypted, err := decodeBase64(req.EncryptedB64)
		if err != nil {
			http.Error(w, "Invalid encrypted data", http.StatusBadRequest)
			return
		}

		// Store encrypted text (server cannot decrypt)
		h.clipboard.SetEncryptedText(encrypted)
		size = len(encrypted)
	} else {
		// Normal plaintext mode
		if req.Text == "" && req.EncryptedB64 == "" {
			http.Error(w, "No content provided", http.StatusBadRequest)
			return
		}

		// Validate content
		text, err := validate.ClipboardContent(req.Text)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		content = []byte(text)
		size = len(text)

		// Store content
		if err := h.clipboard.SetText(content); err != nil {
			http.Error(w, "Failed to set clipboard", http.StatusInternalServerError)
			return
		}
	}

	resp := ClipboardTextResponse{
		HasContent: true,
		Size:       size,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Failed to encode clipboard response: %v", err)
	}
}

// DeleteText handles DELETE /api/clipboard
func (h *ClipboardHandler) DeleteText(w http.ResponseWriter, r *http.Request) {
	h.clipboard.DeleteText()

	resp := map[string]bool{"deleted": true}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Failed to encode delete response: %v", err)
	}
}

// ClipboardImageResponse is the response for image clipboard metadata.
type ClipboardImageResponse struct {
	HasImage     bool   `json:"hasImage"`
	MimeType     string `json:"mimeType,omitempty"`
	Size         int    `json:"size,omitempty"`
	EncryptedB64 string `json:"encrypted_b64,omitempty"` // E2EE: encrypted image when locked
}

// ClipboardImageRequest is the request body for setting image clipboard.
// When session is locked, client sends encrypted_b64 instead of image.
type ClipboardImageRequest struct {
	Image        string `json:"image,omitempty"`        // Base64 encoded image data (plaintext mode)
	MimeType     string `json:"mimetype"`               // MIME type of the image
	EncryptedB64 string `json:"encrypted_b64,omitempty"` // E2EE: encrypted image when locked
}

// GetImageInfo handles GET /api/clipboard-image
// E2EE: When session is locked, returns encrypted_b64 instead of image data.
func (h *ClipboardHandler) GetImageInfo(w http.ResponseWriter, r *http.Request) {
	// E2EE: If session is locked, return encrypted data for client-side decryption
	if h.session.IsLocked() {
		encrypted, mimeType := h.clipboard.GetEncryptedImage()
		if encrypted == nil {
			resp := ClipboardImageResponse{HasImage: false}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				log.Printf("Failed to encode image info response: %v", err)
			}
			return
		}

		resp := ClipboardImageResponse{
			HasImage:     true,
			MimeType:     mimeType,
			Size:         len(encrypted),
			EncryptedB64: base64.StdEncoding.EncodeToString(encrypted),
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("Failed to encode image info response: %v", err)
		}
		return
	}

	// Normal plaintext mode
	info := h.clipboard.ImageInfo()

	resp := ClipboardImageResponse{
		HasImage: info.HasContent,
		MimeType: info.MimeType,
		Size:     info.Size,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Failed to encode image info response: %v", err)
	}
}

// GetImageData handles GET /api/clipboard-image/data
func (h *ClipboardHandler) GetImageData(w http.ResponseWriter, r *http.Request) {
	data, mimeType, err := h.clipboard.GetImage()
	if err != nil {
		if err == store.ErrClipboardEmpty || err == store.ErrClipboardExpired {
			http.Error(w, "No image in clipboard", http.StatusNotFound)
			return
		}
		http.Error(w, "Failed to get image", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", mimeType)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(data)
}

// SetImage handles POST /api/clipboard-image
// E2EE: When session is locked, accepts encrypted_b64 instead of image.
// Client encrypts locally, sends ciphertext. Server stores without decrypting.
func (h *ClipboardHandler) SetImage(w http.ResponseWriter, r *http.Request) {
	var req ClipboardImageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate MIME type
	if !validate.IsImageMIMEType(req.MimeType) {
		http.Error(w, "Invalid image type", http.StatusBadRequest)
		return
	}

	var size int

	// E2EE: If session is locked and encrypted data provided, store as encrypted
	if h.session.IsLocked() && req.EncryptedB64 != "" {
		// Decode encrypted data
		encrypted, err := decodeBase64(req.EncryptedB64)
		if err != nil {
			http.Error(w, "Invalid encrypted data", http.StatusBadRequest)
			return
		}

		// Store encrypted image (server cannot decrypt)
		h.clipboard.SetEncryptedImage(encrypted, req.MimeType)
		size = len(encrypted)
	} else {
		// Normal plaintext mode
		if req.Image == "" {
			http.Error(w, "No image data provided", http.StatusBadRequest)
			return
		}

		// Decode base64 image data
		data, err := decodeBase64(req.Image)
		if err != nil {
			http.Error(w, "Invalid base64 image data", http.StatusBadRequest)
			return
		}

		if len(data) > validate.MaxClipboardSize {
			http.Error(w, "Image too large", http.StatusRequestEntityTooLarge)
			return
		}

		// Store image
		if err := h.clipboard.SetImage(data, req.MimeType); err != nil {
			http.Error(w, "Failed to store image", http.StatusInternalServerError)
			return
		}
		size = len(data)
	}

	resp := ClipboardImageResponse{
		HasImage: true,
		MimeType: req.MimeType,
		Size:     size,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Failed to encode image response: %v", err)
	}
}

// DeleteImage handles DELETE /api/clipboard-image
func (h *ClipboardHandler) DeleteImage(w http.ResponseWriter, r *http.Request) {
	h.clipboard.DeleteImage()

	resp := map[string]bool{"deleted": true}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Failed to encode delete response: %v", err)
	}
}
