package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/fileez/fileez/internal/store"
	"github.com/fileez/fileez/internal/validate"
)

// decodeBase64 decodes a base64 string to bytes.
func decodeBase64Files(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// FilesHandler handles file operations.
type FilesHandler struct {
	files       *store.FileStore
	session     *store.SessionManager
	maxFileSize int64
}

// NewFilesHandler creates a new files handler.
func NewFilesHandler(files *store.FileStore, session *store.SessionManager, maxFileSize int64) *FilesHandler {
	return &FilesHandler{
		files:       files,
		session:     session,
		maxFileSize: maxFileSize,
	}
}

// FileResponse is the response for a single file.
type FileResponse struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	MimeType     string `json:"mimetype"`
	Size         int64  `json:"size"`
	UploadedAt   string `json:"uploadedAt,omitempty"`
	ExpiresAt    string `json:"expiresAt,omitempty"`
	EncryptedB64 string `json:"encrypted_b64,omitempty"` // E2EE: encrypted file data when locked
}

// List handles GET /api/files
// E2EE: When session is locked, returns encrypted_b64 for each file.
func (h *FilesHandler) List(w http.ResponseWriter, r *http.Request) {
	// E2EE: If session is locked, return encrypted files for client-side decryption
	if h.session.IsLocked() {
		encryptedFiles := h.files.GetEncryptedFiles()
		resp := make([]FileResponse, 0, len(encryptedFiles))

		for _, f := range encryptedFiles {
			resp = append(resp, FileResponse{
				ID:           f.ID,
				Name:         f.Name,
				MimeType:     f.MimeType,
				Size:         f.Size,
				EncryptedB64: f.EncryptedB64,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}

	// Normal plaintext mode
	files := h.files.List()

	resp := make([]FileResponse, 0, len(files))

	for _, f := range files {
		resp = append(resp, FileResponse{
			ID:         f.ID,
			Name:       f.Filename,
			MimeType:   f.MimeType,
			Size:       f.Size,
			UploadedAt: f.CreatedAt.Format("2006-01-02T15:04:05Z"),
			ExpiresAt:  f.ExpiresAt.Format("2006-01-02T15:04:05Z"),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Upload handles POST /api/upload
func (h *FilesHandler) Upload(w http.ResponseWriter, r *http.Request) {
	// Limit request size
	r.Body = http.MaxBytesReader(w, r.Body, h.maxFileSize)

	// Parse multipart form
	if err := r.ParseMultipartForm(h.maxFileSize); err != nil {
		if err.Error() == "http: request body too large" {
			http.Error(w, "File too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	// Get file from form
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "No file provided", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Validate filename
	filename, err := validate.Filename(header.Filename)
	if err != nil {
		http.Error(w, "Invalid filename", http.StatusBadRequest)
		return
	}

	// Get and validate MIME type
	mimeType := header.Header.Get("Content-Type")
	mimeType = validate.MIMETypeOrDefault(mimeType, "application/octet-stream")

	// Read file content
	content, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Failed to read file", http.StatusInternalServerError)
		return
	}

	// Store file
	id, err := h.files.Store(filename, mimeType, content)
	if err != nil {
		switch err {
		case store.ErrFileTooLarge:
			http.Error(w, "File too large", http.StatusRequestEntityTooLarge)
		case store.ErrStorageFull:
			http.Error(w, "Storage full", http.StatusInsufficientStorage)
		default:
			http.Error(w, "Failed to store file", http.StatusInternalServerError)
		}
		return
	}

	// Get metadata for response
	metadata, err := h.files.GetMetadata(id)
	if err != nil {
		http.Error(w, "File stored but failed to get metadata", http.StatusInternalServerError)
		return
	}

	resp := FileResponse{
		ID:         metadata.ID,
		Name:       metadata.Filename,
		MimeType:   metadata.MimeType,
		Size:       metadata.Size,
		UploadedAt: metadata.CreatedAt.Format("2006-01-02T15:04:05Z"),
		ExpiresAt:  metadata.ExpiresAt.Format("2006-01-02T15:04:05Z"),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// EncryptedUploadRequest is the request for uploading encrypted files.
// E2EE: Client encrypts file locally and sends ciphertext.
type EncryptedUploadRequest struct {
	ID           string `json:"id"`           // Client-generated file ID
	Name         string `json:"name"`         // Original filename
	MimeType     string `json:"mimetype"`     // Original MIME type
	Size         int64  `json:"size"`         // Original unencrypted size
	EncryptedB64 string `json:"encrypted_b64"` // Base64-encoded encrypted data
}

// UploadEncrypted handles POST /api/upload/encrypted
// E2EE: Receives encrypted file data from client. Server cannot decrypt.
func (h *FilesHandler) UploadEncrypted(w http.ResponseWriter, r *http.Request) {
	// Only allow when session is locked
	if !h.session.IsLocked() {
		http.Error(w, "Session must be locked for encrypted uploads", http.StatusBadRequest)
		return
	}

	var req EncryptedUploadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate filename
	filename, err := validate.Filename(req.Name)
	if err != nil {
		http.Error(w, "Invalid filename", http.StatusBadRequest)
		return
	}

	// Validate MIME type
	mimeType := validate.MIMETypeOrDefault(req.MimeType, "application/octet-stream")

	// Decode encrypted data
	encrypted, err := decodeBase64Files(req.EncryptedB64)
	if err != nil {
		http.Error(w, "Invalid encrypted data", http.StatusBadRequest)
		return
	}

	// Check size limits (encrypted data will be slightly larger than original)
	if int64(len(encrypted)) > h.maxFileSize+1024 { // Allow for encryption overhead
		http.Error(w, "File too large", http.StatusRequestEntityTooLarge)
		return
	}

	// Store as encrypted file
	id := req.ID
	if id == "" {
		id = fmt.Sprintf("%d-%s", r.Context().Value("timestamp"), filename)
	}

	// Create encrypted file info and add to store
	encryptedFile := store.EncryptedFileInfo{
		ID:           id,
		Name:         filename,
		MimeType:     mimeType,
		Size:         req.Size,
		EncryptedB64: req.EncryptedB64,
	}

	// Add to encrypted files list
	h.files.AddEncryptedFile(encryptedFile)

	resp := FileResponse{
		ID:       id,
		Name:     filename,
		MimeType: mimeType,
		Size:     req.Size,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// Download handles GET /api/files/:id/download
func (h *FilesHandler) Download(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	// Validate file ID
	id, err := validate.FileID(id)
	if err != nil {
		http.Error(w, "Invalid file ID", http.StatusBadRequest)
		return
	}

	// Get file
	file, content, err := h.files.Get(id)
	if err != nil {
		switch err {
		case store.ErrFileNotFound:
			http.Error(w, "File not found", http.StatusNotFound)
		case store.ErrFileExpired:
			http.Error(w, "File expired", http.StatusGone)
		default:
			http.Error(w, "Failed to get file", http.StatusInternalServerError)
		}
		return
	}

	// Set headers for download
	w.Header().Set("Content-Type", file.MimeType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, file.Filename))
	w.Header().Set("Content-Length", strconv.FormatInt(int64(len(content)), 10))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(content)
}

// GetMetadata handles GET /api/files/:id
func (h *FilesHandler) GetMetadata(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	// Validate file ID
	id, err := validate.FileID(id)
	if err != nil {
		http.Error(w, "Invalid file ID", http.StatusBadRequest)
		return
	}

	// Get metadata
	file, err := h.files.GetMetadata(id)
	if err != nil {
		switch err {
		case store.ErrFileNotFound:
			http.Error(w, "File not found", http.StatusNotFound)
		case store.ErrFileExpired:
			http.Error(w, "File expired", http.StatusGone)
		default:
			http.Error(w, "Failed to get file", http.StatusInternalServerError)
		}
		return
	}

	resp := FileResponse{
		ID:         file.ID,
		Name:       file.Filename,
		MimeType:   file.MimeType,
		Size:       file.Size,
		UploadedAt: file.CreatedAt.Format("2006-01-02T15:04:05Z"),
		ExpiresAt:  file.ExpiresAt.Format("2006-01-02T15:04:05Z"),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Delete handles DELETE /api/files/:id
func (h *FilesHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	// Validate file ID
	id, err := validate.FileID(id)
	if err != nil {
		http.Error(w, "Invalid file ID", http.StatusBadRequest)
		return
	}

	// Delete file (secure shred)
	if err := h.files.Delete(id); err != nil {
		if err == store.ErrFileNotFound {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Failed to delete file", http.StatusInternalServerError)
		return
	}

	resp := map[string]interface{}{
		"deleted":  true,
		"id":       id,
		"shredded": true,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
