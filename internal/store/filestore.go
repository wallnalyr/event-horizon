package store

import (
	"encoding/base64"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/fileez/fileez/internal/crypto"
	"github.com/fileez/fileez/internal/secure"
	"github.com/fileez/fileez/internal/validate"
)

var (
	// ErrFileNotFound indicates the file does not exist.
	ErrFileNotFound = errors.New("file not found")
	// ErrFileExpired indicates the file has expired.
	ErrFileExpired = errors.New("file expired")
	// ErrFileTooLarge indicates the file exceeds the size limit.
	ErrFileTooLarge = errors.New("file too large")
	// ErrStorageFull indicates no more storage space is available.
	ErrStorageFull = errors.New("storage full")
)

// StoredFile represents a file stored in memory.
type StoredFile struct {
	mu sync.RWMutex

	// Identifiers
	ID string

	// Content (either plaintext or encrypted)
	data      *secure.FortifiedBuffer // Plaintext when unlocked (with memory obfuscation)
	encrypted []byte                  // Ciphertext when locked

	// Metadata
	Filename  string
	MimeType  string
	Size      int64
	CreatedAt time.Time
	ExpiresAt time.Time
}

// FileStore manages secure in-memory file storage.
type FileStore struct {
	mu sync.RWMutex

	files map[string]*StoredFile

	// Configuration
	maxFileSize int64
	expiry      time.Duration

	// Session manager for encryption key
	session *SessionManager

	// Memory tracker
	memory *secure.MemoryTracker

	// Shutdown signal
	done chan struct{}
}

// NewFileStore creates a new file store.
func NewFileStore(session *SessionManager, memory *secure.MemoryTracker, maxFileSize int64, expiry time.Duration) *FileStore {
	if maxFileSize == 0 {
		maxFileSize = 100 * 1024 * 1024 // 100MB
	}
	if expiry == 0 {
		expiry = 24 * time.Hour
	}

	store := &FileStore{
		files:       make(map[string]*StoredFile),
		maxFileSize: maxFileSize,
		expiry:      expiry,
		session:     session,
		memory:      memory,
		done:        make(chan struct{}),
	}

	// Start expiry checker
	go store.expiryLoop()

	return store
}

// Store stores a file and returns its ID (plaintext in SecureBuffer).
// E2EE: This is only called when session is unlocked. When locked, encrypted
// blobs are stored via SetEncryptedFiles.
// WARNING: The content slice is always shredded after this call, even on error.
// Caller should not reuse the slice.
func (fs *FileStore) Store(filename string, mimeType string, content []byte) (string, error) {
	// Always shred input when done, regardless of success/failure
	defer secure.Shred(content)

	// Validate inputs
	filename, err := validate.Filename(filename)
	if err != nil {
		return "", err
	}

	mimeType = validate.MIMETypeOrDefault(mimeType, "application/octet-stream")

	contentLen := int64(len(content))

	// Check file size
	if contentLen > fs.maxFileSize {
		return "", ErrFileTooLarge
	}

	// Check memory limit
	if fs.memory != nil {
		if err := fs.memory.Allocate(contentLen); err != nil {
			return "", ErrStorageFull
		}
	}

	// Generate file ID
	id, err := crypto.GenerateFileID()
	if err != nil {
		if fs.memory != nil {
			fs.memory.Free(contentLen)
		}
		return "", err
	}

	now := time.Now()

	// Store in fortified buffer (plaintext - session is unlocked)
	// Uses scatter + obfuscation + tripwire for memory protection
	buf, err := secure.NewFortifiedBuffer(content)
	if err != nil {
		if fs.memory != nil {
			fs.memory.Free(contentLen)
		}
		return "", err
	}

	file := &StoredFile{
		ID:        id,
		data:      buf,
		Filename:  filename,
		MimeType:  mimeType,
		Size:      int64(buf.Size()),
		CreatedAt: now,
		ExpiresAt: now.Add(fs.expiry),
	}

	fs.mu.Lock()
	fs.files[id] = file
	fs.mu.Unlock()

	return id, nil
}

// Get retrieves a file by ID (plaintext from SecureBuffer).
// E2EE: This is only called when session is unlocked. When locked, encrypted
// blobs are retrieved via GetEncryptedFiles.
func (fs *FileStore) Get(id string) (*StoredFile, []byte, error) {
	// Validate ID
	id, err := validate.FileID(id)
	if err != nil {
		return nil, nil, ErrFileNotFound
	}

	fs.mu.RLock()
	file, exists := fs.files[id]
	fs.mu.RUnlock()

	if !exists {
		return nil, nil, ErrFileNotFound
	}

	file.mu.RLock()
	defer file.mu.RUnlock()

	// Check expiry
	if time.Now().After(file.ExpiresAt) {
		return nil, nil, ErrFileExpired
	}

	// Get plaintext content from SecureBuffer
	if file.data == nil {
		// No plaintext data - might be encrypted (locked state)
		return nil, nil, ErrFileNotFound
	}

	var content []byte
	err = file.data.Use(func(data []byte) error {
		content = make([]byte, len(data))
		copy(content, data)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	return file, content, nil
}

// GetMetadata retrieves file metadata without content.
func (fs *FileStore) GetMetadata(id string) (*StoredFile, error) {
	id, err := validate.FileID(id)
	if err != nil {
		return nil, ErrFileNotFound
	}

	fs.mu.RLock()
	file, exists := fs.files[id]
	fs.mu.RUnlock()

	if !exists {
		return nil, ErrFileNotFound
	}

	file.mu.RLock()
	defer file.mu.RUnlock()

	if time.Now().After(file.ExpiresAt) {
		return nil, ErrFileExpired
	}

	return file, nil
}

// Delete securely shreds and removes a file.
func (fs *FileStore) Delete(id string) error {
	id, err := validate.FileID(id)
	if err != nil {
		return ErrFileNotFound
	}

	fs.mu.Lock()
	file, exists := fs.files[id]
	if !exists {
		fs.mu.Unlock()
		return ErrFileNotFound
	}
	delete(fs.files, id)
	fs.mu.Unlock()

	// Shred file data
	fs.shredFile(file)

	return nil
}

// List returns metadata for all stored files.
func (fs *FileStore) List() []FileInfo {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	now := time.Now()
	var files []FileInfo

	for _, file := range fs.files {
		file.mu.RLock()
		if !now.After(file.ExpiresAt) {
			files = append(files, FileInfo{
				ID:        file.ID,
				Filename:  file.Filename,
				MimeType:  file.MimeType,
				Size:      file.Size,
				CreatedAt: file.CreatedAt,
				ExpiresAt: file.ExpiresAt,
			})
		}
		file.mu.RUnlock()
	}

	// Sort by creation time (newest first)
	sort.Slice(files, func(i, j int) bool {
		return files[i].CreatedAt.After(files[j].CreatedAt)
	})

	return files
}

// FileInfo contains file metadata for API responses.
type FileInfo struct {
	ID        string    `json:"id"`
	Filename  string    `json:"filename"`
	MimeType  string    `json:"mime_type"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Count returns the number of stored files.
func (fs *FileStore) Count() int {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return len(fs.files)
}

// shredFile securely destroys a file.
func (fs *FileStore) shredFile(file *StoredFile) {
	if file == nil {
		return
	}

	file.mu.Lock()
	defer file.mu.Unlock()

	// Free memory
	if fs.memory != nil {
		fs.memory.Free(file.Size)
	}

	// Shred data (FortifiedBuffer handles its own secure destruction)
	if file.data != nil {
		secure.ShredFortifiedBuffer(file.data)
		file.data = nil
	}

	if file.encrypted != nil {
		secure.Shred(file.encrypted)
		file.encrypted = nil
	}
}

// ShredAll securely destroys all stored files.
func (fs *FileStore) ShredAll() int {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	count := len(fs.files)

	for id, file := range fs.files {
		fs.shredFile(file)
		delete(fs.files, id)
	}

	return count
}

// Close stops the expiry loop and shreds all files.
// Should be called on application shutdown.
func (fs *FileStore) Close() {
	// Signal goroutine to stop
	close(fs.done)

	// Shred all remaining files
	fs.ShredAll()
}

// expiryLoop periodically checks for expired files.
func (fs *FileStore) expiryLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			fs.cleanupExpired()
		case <-fs.done:
			return
		}
	}
}

// cleanupExpired removes expired files.
func (fs *FileStore) cleanupExpired() {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	now := time.Now()
	var expired []string

	for id, file := range fs.files {
		file.mu.RLock()
		isExpired := now.After(file.ExpiresAt)
		file.mu.RUnlock()

		if isExpired {
			expired = append(expired, id)
		}
	}

	for _, id := range expired {
		if file, exists := fs.files[id]; exists {
			fs.shredFile(file)
			delete(fs.files, id)
		}
	}
}

// Stats returns storage statistics.
type FileStoreStats struct {
	FileCount   int   `json:"file_count"`
	TotalSize   int64 `json:"total_size"`
	MaxFileSize int64 `json:"max_file_size"`
}

// Stats returns current storage statistics.
func (fs *FileStore) Stats() FileStoreStats {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	var totalSize int64
	for _, file := range fs.files {
		file.mu.RLock()
		totalSize += file.Size
		file.mu.RUnlock()
	}

	return FileStoreStats{
		FileCount:   len(fs.files),
		TotalSize:   totalSize,
		MaxFileSize: fs.maxFileSize,
	}
}

// EncryptedFileInfo contains file metadata and encrypted data for E2EE.
type EncryptedFileInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	MimeType    string `json:"mimetype"`
	Size        int64  `json:"size"`
	EncryptedB64 string `json:"encrypted_b64"`
}

// SetEncryptedFiles stores already-encrypted file blobs from the client.
// Used during E2EE lock operation - server cannot decrypt this data.
// Shreds all existing files first.
func (fs *FileStore) SetEncryptedFiles(files []EncryptedFileInfo) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	// Shred all existing files
	for id, file := range fs.files {
		fs.shredFile(file)
		delete(fs.files, id)
	}

	// Store encrypted blobs
	now := time.Now()
	for _, f := range files {
		encrypted, err := base64.StdEncoding.DecodeString(f.EncryptedB64)
		if err != nil {
			continue
		}

		fs.files[f.ID] = &StoredFile{
			ID:        f.ID,
			encrypted: encrypted,
			Filename:  f.Name,
			MimeType:  f.MimeType,
			Size:      f.Size,
			CreatedAt: now,
			ExpiresAt: now.Add(fs.expiry),
		}
	}
}

// AddEncryptedFile adds a single encrypted file to the store.
// Used for E2EE uploads when session is locked - client encrypts locally.
func (fs *FileStore) AddEncryptedFile(f EncryptedFileInfo) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	encrypted, err := base64.StdEncoding.DecodeString(f.EncryptedB64)
	if err != nil {
		return
	}

	now := time.Now()
	fs.files[f.ID] = &StoredFile{
		ID:        f.ID,
		encrypted: encrypted,
		Filename:  f.Name,
		MimeType:  f.MimeType,
		Size:      f.Size,
		CreatedAt: now,
		ExpiresAt: now.Add(fs.expiry),
	}
}

// GetEncryptedFiles returns all encrypted file blobs for client-side decryption.
func (fs *FileStore) GetEncryptedFiles() []EncryptedFileInfo {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	var result []EncryptedFileInfo
	for _, file := range fs.files {
		file.mu.RLock()
		if file.encrypted != nil {
			result = append(result, EncryptedFileInfo{
				ID:          file.ID,
				Name:        file.Filename,
				MimeType:    file.MimeType,
				Size:        file.Size,
				EncryptedB64: base64.StdEncoding.EncodeToString(file.encrypted),
			})
		}
		file.mu.RUnlock()
	}
	return result
}

// ClearEncryptedData shreds all encrypted file blobs.
// Called after client successfully decrypts and re-uploads plaintext data.
func (fs *FileStore) ClearEncryptedData() {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	for id, file := range fs.files {
		file.mu.Lock()
		if file.encrypted != nil {
			secure.Shred(file.encrypted)
			file.encrypted = nil
		}
		// If no plaintext data either, remove the file
		if file.data == nil {
			file.mu.Unlock()
			delete(fs.files, id)
		} else {
			file.mu.Unlock()
		}
	}
}
