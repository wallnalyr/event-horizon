// Package store provides secure in-memory storage for files, clipboard, and sessions.
package store

import (
	"errors"
	"sync"
	"time"

	"github.com/fileez/fileez/internal/crypto"
	"github.com/fileez/fileez/internal/secure"
)

var (
	// ErrSessionLocked indicates the session is locked.
	ErrSessionLocked = errors.New("session is locked")
	// ErrSessionNotLocked indicates the session is not locked.
	ErrSessionNotLocked = errors.New("session is not locked")
	// ErrInvalidPassword indicates the password is incorrect.
	ErrInvalidPassword = errors.New("invalid password")
	// ErrSessionExpired indicates the session has expired.
	ErrSessionExpired = errors.New("session expired")
)

// Session represents an active session with encrypted data.
// E2EE model: server only stores keyHash for verification, never the actual key.
type Session struct {
	mu sync.RWMutex

	// Session state
	token     string
	locked    bool
	createdAt time.Time
	lockedAt  time.Time

	// E2EE verification (server cannot decrypt - only verifies keyHash)
	// keyHash: SHA-256 of client's derived key (for password verification)
	// salt: PBKDF2 salt (sent to client for key derivation on unlock)
	keyHash []byte
	salt    []byte

	// Callbacks for lock/unlock events
	onLock   func()
	onUnlock func()
}

// SessionManager manages session state and encryption.
type SessionManager struct {
	mu      sync.RWMutex
	session *Session
}

// NewSessionManager creates a new session manager.
func NewSessionManager() *SessionManager {
	return &SessionManager{}
}

// CreateSession creates a new unlocked session.
// Returns the session token.
func (sm *SessionManager) CreateSession() (string, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Generate session token
	token, err := crypto.GenerateSessionTokenString()
	if err != nil {
		return "", err
	}

	sm.session = &Session{
		token:     token,
		locked:    false,
		createdAt: time.Now(),
	}

	return token, nil
}

// GetSession returns the current session if it exists.
func (sm *SessionManager) GetSession() *Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.session
}

// IsLocked returns whether the session is locked.
func (sm *SessionManager) IsLocked() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.session == nil {
		return false
	}

	sm.session.mu.RLock()
	defer sm.session.mu.RUnlock()
	return sm.session.locked
}

// Lock locks the session with E2EE.
// Stores keyHash and salt from client for verification (server cannot derive key).
func (sm *SessionManager) Lock(keyHash, salt []byte) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.session == nil {
		// Create a new session if none exists
		token, err := crypto.GenerateSessionTokenString()
		if err != nil {
			return err
		}
		sm.session = &Session{
			token:     token,
			createdAt: time.Now(),
		}
	}

	sm.session.mu.Lock()
	defer sm.session.mu.Unlock()

	if sm.session.locked {
		return ErrSessionLocked
	}

	// Store keyHash and salt for verification (cannot derive key from these)
	sm.session.keyHash = make([]byte, len(keyHash))
	copy(sm.session.keyHash, keyHash)

	sm.session.salt = make([]byte, len(salt))
	copy(sm.session.salt, salt)

	sm.session.locked = true
	sm.session.lockedAt = time.Now()

	if sm.session.onLock != nil {
		sm.session.onLock()
	}

	return nil
}

// VerifyKeyHash checks if the provided keyHash matches using constant-time comparison.
// Returns nil if keyHash is correct, ErrInvalidPassword if wrong.
func (sm *SessionManager) VerifyKeyHash(keyHash []byte) error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.session == nil {
		return ErrSessionNotLocked
	}

	sm.session.mu.RLock()
	defer sm.session.mu.RUnlock()

	if !sm.session.locked {
		return ErrSessionNotLocked
	}

	// Verify keyHash exists (defensive check)
	if sm.session.keyHash == nil {
		return errors.New("session keyHash is nil")
	}

	// Constant-time comparison to prevent timing attacks
	if !crypto.ConstantTimeCompare(sm.session.keyHash, keyHash) {
		return ErrInvalidPassword
	}

	return nil
}

// Unlock unlocks the session after keyHash verification.
// The keyHash should already be verified via VerifyKeyHash before calling this.
func (sm *SessionManager) Unlock() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.session == nil {
		return ErrSessionNotLocked
	}

	sm.session.mu.Lock()
	defer sm.session.mu.Unlock()

	if !sm.session.locked {
		return ErrSessionNotLocked
	}

	// Clear keyHash and salt
	if sm.session.keyHash != nil {
		secure.Shred(sm.session.keyHash)
		sm.session.keyHash = nil
	}

	if sm.session.salt != nil {
		secure.Shred(sm.session.salt)
		sm.session.salt = nil
	}

	sm.session.locked = false
	sm.session.lockedAt = time.Time{}

	if sm.session.onUnlock != nil {
		sm.session.onUnlock()
	}

	return nil
}

// ForceUnlock shreds all data and unlocks without password.
// This is the "emergency" option when password is forgotten.
func (sm *SessionManager) ForceUnlock(shredCallback func()) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.session == nil {
		return ErrSessionNotLocked
	}

	sm.session.mu.Lock()
	defer sm.session.mu.Unlock()

	if !sm.session.locked {
		return ErrSessionNotLocked
	}

	// Call shred callback to destroy all encrypted data
	if shredCallback != nil {
		shredCallback()
	}

	// Clear keyHash
	if sm.session.keyHash != nil {
		secure.Shred(sm.session.keyHash)
		sm.session.keyHash = nil
	}

	// Clear salt
	if sm.session.salt != nil {
		secure.Shred(sm.session.salt)
		sm.session.salt = nil
	}

	sm.session.locked = false
	sm.session.lockedAt = time.Time{}

	return nil
}

// GetSalt returns the PBKDF2 salt for client-side key derivation.
// Returns nil if session is not locked.
func (sm *SessionManager) GetSalt() []byte {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.session == nil || !sm.session.locked {
		return nil
	}

	sm.session.mu.RLock()
	defer sm.session.mu.RUnlock()

	if sm.session.salt == nil {
		return nil
	}

	// Return a copy to prevent external modification
	result := make([]byte, len(sm.session.salt))
	copy(result, sm.session.salt)
	return result
}

// GetToken returns the session token.
func (sm *SessionManager) GetToken() string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.session == nil {
		return ""
	}

	sm.session.mu.RLock()
	defer sm.session.mu.RUnlock()

	return sm.session.token
}

// Status returns the current session status.
type SessionStatus struct {
	Exists    bool      `json:"exists"`
	Locked    bool      `json:"locked"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	LockedAt  time.Time `json:"locked_at,omitempty"`
}

// Status returns the current session status.
func (sm *SessionManager) Status() SessionStatus {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.session == nil {
		return SessionStatus{Exists: false}
	}

	sm.session.mu.RLock()
	defer sm.session.mu.RUnlock()

	return SessionStatus{
		Exists:    true,
		Locked:    sm.session.locked,
		CreatedAt: sm.session.createdAt,
		LockedAt:  sm.session.lockedAt,
	}
}

// SetLockCallback sets a callback for lock events.
func (sm *SessionManager) SetLockCallback(fn func()) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.session != nil {
		sm.session.mu.Lock()
		sm.session.onLock = fn
		sm.session.mu.Unlock()
	}
}

// SetUnlockCallback sets a callback for unlock events.
func (sm *SessionManager) SetUnlockCallback(fn func()) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.session != nil {
		sm.session.mu.Lock()
		sm.session.onUnlock = fn
		sm.session.mu.Unlock()
	}
}

// Destroy securely wipes the session.
func (sm *SessionManager) Destroy() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.session == nil {
		return
	}

	sm.session.mu.Lock()
	defer sm.session.mu.Unlock()

	if sm.session.keyHash != nil {
		secure.Shred(sm.session.keyHash)
	}

	if sm.session.salt != nil {
		secure.Shred(sm.session.salt)
	}

	sm.session = nil
}
