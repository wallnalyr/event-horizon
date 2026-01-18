package store

import (
	"errors"
	"sync"
	"time"

	"github.com/fileez/fileez/internal/secure"
)

var (
	// ErrClipboardEmpty indicates the clipboard is empty.
	ErrClipboardEmpty = errors.New("clipboard is empty")
	// ErrClipboardExpired indicates the clipboard content has expired.
	ErrClipboardExpired = errors.New("clipboard content expired")
)

// ClipboardType represents the type of clipboard content.
type ClipboardType int

const (
	// ClipboardTypeText represents text clipboard content.
	ClipboardTypeText ClipboardType = iota
	// ClipboardTypeImage represents image clipboard content.
	ClipboardTypeImage
)

// ClipboardEntry represents a single clipboard entry.
type ClipboardEntry struct {
	mu sync.RWMutex

	// Content (either plaintext or encrypted)
	data      *secure.FortifiedBuffer // Plaintext when unlocked (with memory obfuscation)
	encrypted []byte                  // Ciphertext when locked

	// Metadata
	contentType ClipboardType
	mimeType    string // For images: "image/png", "image/jpeg", etc.
	size        int
	createdAt   time.Time
	expiresAt   time.Time
}

// ClipboardStore manages secure clipboard storage.
type ClipboardStore struct {
	mu sync.RWMutex

	text  *ClipboardEntry
	image *ClipboardEntry

	// Configuration
	expiry time.Duration

	// Session manager for encryption key
	session *SessionManager

	// Memory tracker
	memory *secure.MemoryTracker

	// Shutdown signal
	done chan struct{}
}

// NewClipboardStore creates a new clipboard store.
func NewClipboardStore(session *SessionManager, memory *secure.MemoryTracker, expiry time.Duration) *ClipboardStore {
	if expiry == 0 {
		expiry = 1 * time.Hour
	}

	store := &ClipboardStore{
		expiry:  expiry,
		session: session,
		memory:  memory,
		done:    make(chan struct{}),
	}

	// Start expiry checker
	go store.expiryLoop()

	return store
}

// SetText stores text content in the clipboard (plaintext in SecureBuffer).
// E2EE: This is only called when session is unlocked. When locked, encrypted
// blobs are stored via SetEncryptedText.
// WARNING: The content slice is always shredded after this call, even on error.
// Caller should not reuse the slice.
func (cs *ClipboardStore) SetText(content []byte) error {
	// Always shred input when done, regardless of success/failure
	defer secure.Shred(content)

	contentLen := len(content)

	// Pre-create the new entry BEFORE acquiring lock to minimize lock hold time
	now := time.Now()

	// Store in fortified buffer (plaintext - session is unlocked)
	// Uses scatter + obfuscation + tripwire for memory protection
	buf, err := secure.NewFortifiedBuffer(content)
	if err != nil {
		return err
	}

	newEntry := &ClipboardEntry{
		data:        buf,
		contentType: ClipboardTypeText,
		size:        buf.Size(),
		createdAt:   now,
		expiresAt:   now.Add(cs.expiry),
	}

	// Now acquire lock briefly to swap entries
	cs.mu.Lock()

	// Check memory limit
	if cs.memory != nil {
		if err := cs.memory.Allocate(int64(contentLen)); err != nil {
			cs.mu.Unlock()
			// Clean up the new entry we created
			if newEntry.data != nil {
				newEntry.data.Destroy()
			}
			return err
		}
	}

	// Swap entries - grab old entry for deferred shredding
	oldEntry := cs.text
	cs.text = newEntry

	cs.mu.Unlock()

	// Shred old entry OUTSIDE the lock to avoid blocking other operations
	// This is safe because we've already removed it from the store
	if oldEntry != nil {
		cs.shredEntryAsync(oldEntry)
	}

	return nil
}

// GetText retrieves text content from the clipboard (plaintext from SecureBuffer).
// E2EE: This is only called when session is unlocked. When locked, encrypted
// blobs are retrieved via GetEncryptedText.
func (cs *ClipboardStore) GetText() ([]byte, error) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	if cs.text == nil {
		return nil, ErrClipboardEmpty
	}

	// Lock the entry to prevent concurrent shredding
	cs.text.mu.RLock()
	defer cs.text.mu.RUnlock()

	// Check expiry
	if time.Now().After(cs.text.expiresAt) {
		return nil, ErrClipboardExpired
	}

	// Return copy of plaintext from SecureBuffer
	if cs.text.data == nil {
		// No plaintext data - might be encrypted (locked state)
		return nil, ErrClipboardEmpty
	}

	var result []byte
	err := cs.text.data.Use(func(d []byte) error {
		result = make([]byte, len(d))
		copy(result, d)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return result, nil
}

// SetImage stores image content in the clipboard (plaintext in SecureBuffer).
// E2EE: This is only called when session is unlocked. When locked, encrypted
// blobs are stored via SetEncryptedImage.
// WARNING: The content slice is always shredded after this call, even on error.
// Caller should not reuse the slice.
func (cs *ClipboardStore) SetImage(content []byte, mimeType string) error {
	// Always shred input when done, regardless of success/failure
	defer secure.Shred(content)

	contentLen := len(content)

	// Pre-create the new entry BEFORE acquiring lock to minimize lock hold time
	now := time.Now()

	// Store in fortified buffer (plaintext - session is unlocked)
	// Uses scatter + obfuscation + tripwire for memory protection
	buf, err := secure.NewFortifiedBuffer(content)
	if err != nil {
		return err
	}

	newEntry := &ClipboardEntry{
		data:        buf,
		contentType: ClipboardTypeImage,
		mimeType:    mimeType,
		size:        buf.Size(),
		createdAt:   now,
		expiresAt:   now.Add(cs.expiry),
	}

	// Now acquire lock briefly to swap entries
	cs.mu.Lock()

	// Check memory limit
	if cs.memory != nil {
		if err := cs.memory.Allocate(int64(contentLen)); err != nil {
			cs.mu.Unlock()
			// Clean up the new entry we created
			if newEntry.data != nil {
				newEntry.data.Destroy()
			}
			return err
		}
	}

	// Swap entries - grab old entry for deferred shredding
	oldEntry := cs.image
	cs.image = newEntry

	cs.mu.Unlock()

	// Shred old entry OUTSIDE the lock to avoid blocking other operations
	if oldEntry != nil {
		cs.shredEntryAsync(oldEntry)
	}

	return nil
}

// GetImage retrieves image content from the clipboard (plaintext from SecureBuffer).
// E2EE: This is only called when session is unlocked. When locked, encrypted
// blobs are retrieved via GetEncryptedImage.
func (cs *ClipboardStore) GetImage() ([]byte, string, error) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	if cs.image == nil {
		return nil, "", ErrClipboardEmpty
	}

	// Lock the entry to prevent concurrent shredding
	cs.image.mu.RLock()
	defer cs.image.mu.RUnlock()

	// Check expiry
	if time.Now().After(cs.image.expiresAt) {
		return nil, "", ErrClipboardExpired
	}

	mimeType := cs.image.mimeType

	// Return copy of plaintext from SecureBuffer
	if cs.image.data == nil {
		// No plaintext data - might be encrypted (locked state)
		return nil, "", ErrClipboardEmpty
	}

	var result []byte
	err := cs.image.data.Use(func(d []byte) error {
		result = make([]byte, len(d))
		copy(result, d)
		return nil
	})

	if err != nil {
		return nil, "", err
	}

	return result, mimeType, nil
}

// DeleteText shreds and removes text clipboard content.
func (cs *ClipboardStore) DeleteText() {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.text != nil {
		cs.shredEntry(cs.text)
		cs.text = nil
	}
}

// DeleteImage shreds and removes image clipboard content.
func (cs *ClipboardStore) DeleteImage() {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.image != nil {
		cs.shredEntry(cs.image)
		cs.image = nil
	}
}

// HasText returns whether there is text content.
func (cs *ClipboardStore) HasText() bool {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	if cs.text == nil {
		return false
	}

	cs.text.mu.RLock()
	defer cs.text.mu.RUnlock()

	return !time.Now().After(cs.text.expiresAt)
}

// HasImage returns whether there is image content.
func (cs *ClipboardStore) HasImage() bool {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	if cs.image == nil {
		return false
	}

	cs.image.mu.RLock()
	defer cs.image.mu.RUnlock()

	return !time.Now().After(cs.image.expiresAt)
}

// TextInfo returns metadata about text content without returning the content.
type ClipboardInfo struct {
	HasContent bool      `json:"has_content"`
	Size       int       `json:"size,omitempty"`
	MimeType   string    `json:"mime_type,omitempty"`
	CreatedAt  time.Time `json:"created_at,omitempty"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
}

// TextInfo returns information about text clipboard.
func (cs *ClipboardStore) TextInfo() ClipboardInfo {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	if cs.text == nil {
		return ClipboardInfo{HasContent: false}
	}

	cs.text.mu.RLock()
	defer cs.text.mu.RUnlock()

	if time.Now().After(cs.text.expiresAt) {
		return ClipboardInfo{HasContent: false}
	}

	return ClipboardInfo{
		HasContent: true,
		Size:       cs.text.size,
		MimeType:   "text/plain",
		CreatedAt:  cs.text.createdAt,
		ExpiresAt:  cs.text.expiresAt,
	}
}

// ImageInfo returns information about image clipboard.
func (cs *ClipboardStore) ImageInfo() ClipboardInfo {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	if cs.image == nil {
		return ClipboardInfo{HasContent: false}
	}

	cs.image.mu.RLock()
	defer cs.image.mu.RUnlock()

	if time.Now().After(cs.image.expiresAt) {
		return ClipboardInfo{HasContent: false}
	}

	return ClipboardInfo{
		HasContent: true,
		Size:       cs.image.size,
		MimeType:   cs.image.mimeType,
		CreatedAt:  cs.image.createdAt,
		ExpiresAt:  cs.image.expiresAt,
	}
}

// shredEntry securely destroys a clipboard entry (synchronous).
// Should only be called when you need to ensure shredding completes before returning.
func (cs *ClipboardStore) shredEntry(entry *ClipboardEntry) {
	if entry == nil {
		return
	}

	entry.mu.Lock()
	defer entry.mu.Unlock()

	// Free memory
	if cs.memory != nil {
		cs.memory.Free(int64(entry.size))
	}

	// Shred data (FortifiedBuffer handles its own secure destruction)
	if entry.data != nil {
		secure.ShredFortifiedBuffer(entry.data)
		entry.data = nil
	}

	if entry.encrypted != nil {
		secure.Shred(entry.encrypted)
		entry.encrypted = nil
	}
}

// shredEntryAsync securely destroys a clipboard entry asynchronously.
// The entry must have already been removed from the store before calling this.
// This prevents blocking the store lock during the slow shredding process.
func (cs *ClipboardStore) shredEntryAsync(entry *ClipboardEntry) {
	if entry == nil {
		return
	}

	go func() {
		entry.mu.Lock()
		defer entry.mu.Unlock()

		// Free memory
		if cs.memory != nil {
			cs.memory.Free(int64(entry.size))
		}

		// Shred data (FortifiedBuffer handles its own secure destruction)
		if entry.data != nil {
			secure.ShredFortifiedBuffer(entry.data)
			entry.data = nil
		}

		if entry.encrypted != nil {
			secure.Shred(entry.encrypted)
			entry.encrypted = nil
		}
	}()
}

// ShredAll securely destroys all clipboard content.
func (cs *ClipboardStore) ShredAll() {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.text != nil {
		cs.shredEntry(cs.text)
		cs.text = nil
	}

	if cs.image != nil {
		cs.shredEntry(cs.image)
		cs.image = nil
	}
}

// Close stops the expiry loop and shreds all content.
// Should be called on application shutdown.
func (cs *ClipboardStore) Close() {
	// Signal goroutine to stop
	close(cs.done)

	// Shred all remaining content
	cs.ShredAll()
}

// expiryLoop periodically checks for expired content.
func (cs *ClipboardStore) expiryLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cs.cleanupExpired()
		case <-cs.done:
			return
		}
	}
}

// cleanupExpired removes expired content.
func (cs *ClipboardStore) cleanupExpired() {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	now := time.Now()

	// Since we hold the exclusive store lock, we can safely read entry fields
	// without acquiring entry locks (no other writers can run)
	if cs.text != nil && now.After(cs.text.expiresAt) {
		cs.shredEntry(cs.text)
		cs.text = nil
	}

	if cs.image != nil && now.After(cs.image.expiresAt) {
		cs.shredEntry(cs.image)
		cs.image = nil
	}
}

// SetEncryptedText stores an already-encrypted text blob from the client.
// Used during E2EE lock operation - server cannot decrypt this data.
func (cs *ClipboardStore) SetEncryptedText(encrypted []byte) {
	if len(encrypted) == 0 {
		return
	}

	cs.mu.Lock()
	defer cs.mu.Unlock()

	// Shred any existing text
	if cs.text != nil {
		cs.shredEntry(cs.text)
	}

	// Store encrypted blob (server cannot decrypt)
	cs.text = &ClipboardEntry{
		encrypted:   make([]byte, len(encrypted)),
		contentType: ClipboardTypeText,
		size:        len(encrypted),
		createdAt:   time.Now(),
		expiresAt:   time.Now().Add(cs.expiry),
	}
	copy(cs.text.encrypted, encrypted)
}

// GetEncryptedText returns the encrypted text blob for client-side decryption.
// Returns nil if no encrypted text is stored.
func (cs *ClipboardStore) GetEncryptedText() []byte {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	if cs.text == nil {
		return nil
	}

	cs.text.mu.RLock()
	defer cs.text.mu.RUnlock()

	if cs.text.encrypted == nil {
		return nil
	}

	// Return a copy
	result := make([]byte, len(cs.text.encrypted))
	copy(result, cs.text.encrypted)
	return result
}

// SetEncryptedImage stores an already-encrypted image blob from the client.
// Used during E2EE lock operation - server cannot decrypt this data.
func (cs *ClipboardStore) SetEncryptedImage(encrypted []byte, mimeType string) {
	if len(encrypted) == 0 {
		return
	}

	cs.mu.Lock()
	defer cs.mu.Unlock()

	// Shred any existing image
	if cs.image != nil {
		cs.shredEntry(cs.image)
	}

	// Store encrypted blob (server cannot decrypt)
	cs.image = &ClipboardEntry{
		encrypted:   make([]byte, len(encrypted)),
		contentType: ClipboardTypeImage,
		mimeType:    mimeType,
		size:        len(encrypted),
		createdAt:   time.Now(),
		expiresAt:   time.Now().Add(cs.expiry),
	}
	copy(cs.image.encrypted, encrypted)
}

// GetEncryptedImage returns the encrypted image blob and mime type for client-side decryption.
// Returns nil if no encrypted image is stored.
func (cs *ClipboardStore) GetEncryptedImage() ([]byte, string) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	if cs.image == nil {
		return nil, ""
	}

	cs.image.mu.RLock()
	defer cs.image.mu.RUnlock()

	if cs.image.encrypted == nil {
		return nil, ""
	}

	// Return a copy
	result := make([]byte, len(cs.image.encrypted))
	copy(result, cs.image.encrypted)
	return result, cs.image.mimeType
}

// ClearEncryptedData shreds all encrypted blobs.
// Called after client successfully decrypts and re-uploads plaintext data.
func (cs *ClipboardStore) ClearEncryptedData() {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	// Only clear encrypted data, not plaintext SecureBuffer data
	if cs.text != nil {
		cs.text.mu.Lock()
		if cs.text.encrypted != nil {
			secure.Shred(cs.text.encrypted)
			cs.text.encrypted = nil
		}
		// If no plaintext data either, remove the entry
		if cs.text.data == nil {
			cs.text.mu.Unlock()
			cs.text = nil
		} else {
			cs.text.mu.Unlock()
		}
	}

	if cs.image != nil {
		cs.image.mu.Lock()
		if cs.image.encrypted != nil {
			secure.Shred(cs.image.encrypted)
			cs.image.encrypted = nil
		}
		// If no plaintext data either, remove the entry
		if cs.image.data == nil {
			cs.image.mu.Unlock()
			cs.image = nil
		} else {
			cs.image.mu.Unlock()
		}
	}
}
