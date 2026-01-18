// Package secure provides memory-safe primitives for handling secrets.
// All secrets must use SecureBuffer or SecureKey - never raw []byte.
package secure

import (
	"errors"
	"sync"

	"github.com/awnumar/memguard"
)

const MaxBufferSize = 100 * 1024 * 1024 // 100MB maximum

var (
	// ErrBufferDestroyed indicates the buffer has been securely wiped.
	ErrBufferDestroyed = errors.New("secure buffer has been destroyed")
	// ErrBufferNil indicates a nil buffer was provided.
	ErrBufferNil = errors.New("buffer cannot be nil")
	// ErrBufferTooLarge indicates the buffer exceeds maximum allowed size.
	ErrBufferTooLarge = errors.New("buffer exceeds maximum size (100MB)")
	// ErrBufferEmpty indicates an empty buffer was provided.
	ErrBufferEmpty = errors.New("buffer cannot be empty")
)

// SecureBuffer wraps memguard.LockedBuffer for secure memory handling.
// The underlying memory is:
// - Locked in RAM (cannot be swapped to disk)
// - Protected with guard pages (detect buffer overflows)
// - Securely zeroed on destruction
type SecureBuffer struct {
	buf       *memguard.LockedBuffer
	destroyed bool
	mu        sync.RWMutex
}

// NewSecureBuffer creates a new secure buffer of the given size.
// The buffer is zeroed, memory-locked, and protected with guard pages.
// IMPORTANT: Always call Destroy() when done, preferably via defer.
func NewSecureBuffer(size int) (*SecureBuffer, error) {
	if size <= 0 {
		return nil, errors.New("buffer size must be positive")
	}
	if size > MaxBufferSize {
		return nil, ErrBufferTooLarge
	}

	buf := memguard.NewBuffer(size)
	if buf == nil {
		return nil, errors.New("failed to allocate secure buffer")
	}

	return &SecureBuffer{buf: buf}, nil
}

// NewSecureBufferFromBytes creates a secure buffer from existing bytes.
// The source bytes are automatically zeroed after copying to secure memory.
// IMPORTANT: Always call Destroy() when done, preferably via defer.
func NewSecureBufferFromBytes(data []byte) (*SecureBuffer, error) {
	if data == nil {
		return nil, ErrBufferNil
	}
	if len(data) == 0 {
		return nil, ErrBufferEmpty
	}
	if len(data) > MaxBufferSize {
		return nil, ErrBufferTooLarge
	}

	buf := memguard.NewBufferFromBytes(data)
	if buf == nil {
		return nil, errors.New("failed to allocate secure buffer from bytes")
	}

	// Zero source immediately - don't rely on caller
	memguard.WipeBytes(data)

	return &SecureBuffer{buf: buf}, nil
}

// Bytes returns the underlying byte slice.
// WARNING: Do not store this reference beyond the buffer's lifetime.
// The data will be zeroed when Destroy() is called.
func (s *SecureBuffer) Bytes() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.destroyed {
		return nil, ErrBufferDestroyed
	}

	return s.buf.Bytes(), nil
}

// Size returns the size of the buffer in bytes.
func (s *SecureBuffer) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.destroyed || s.buf == nil {
		return 0
	}

	return s.buf.Size()
}

// Copy creates a new SecureBuffer with a copy of this buffer's contents.
// The new buffer is independent and must be destroyed separately.
func (s *SecureBuffer) Copy() (*SecureBuffer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.destroyed {
		return nil, ErrBufferDestroyed
	}

	// Create new buffer from bytes (memguard copies internally)
	return NewSecureBufferFromBytes(s.buf.Bytes())
}

// Wipe securely zeros the buffer contents without destroying it.
// The buffer can still be used after wiping.
func (s *SecureBuffer) Wipe() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.destroyed {
		return ErrBufferDestroyed
	}

	s.buf.Wipe()
	return nil
}

// Destroy securely wipes and deallocates the buffer.
// After calling Destroy, the buffer cannot be used.
// Safe to call multiple times.
func (s *SecureBuffer) Destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.destroyed || s.buf == nil {
		return
	}

	s.buf.Destroy()
	s.destroyed = true
	s.buf = nil
}

// IsDestroyed returns whether the buffer has been destroyed.
func (s *SecureBuffer) IsDestroyed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.destroyed
}

// Use provides safe access to the buffer contents via a callback.
// This is the preferred way to access buffer data as it ensures
// the buffer isn't destroyed during access.
func (s *SecureBuffer) Use(fn func(data []byte) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.destroyed {
		return ErrBufferDestroyed
	}

	return fn(s.buf.Bytes())
}

// MutableUse provides mutable access to the buffer contents via a callback.
// Use this when you need to modify the buffer contents in place.
func (s *SecureBuffer) MutableUse(fn func(data []byte) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.destroyed {
		return ErrBufferDestroyed
	}

	return fn(s.buf.Bytes())
}

// Seal converts this buffer to a SecureKey (Enclave).
// The buffer is destroyed in the process and should not be used after.
// Use this when you want to store a key that's encrypted in memory.
func (s *SecureBuffer) Seal() (*SecureKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.destroyed {
		return nil, ErrBufferDestroyed
	}

	// Create enclave from the buffer (seals and destroys buffer)
	enclave := s.buf.Seal()
	if enclave == nil {
		return nil, errors.New("failed to seal buffer into enclave")
	}

	s.destroyed = true
	s.buf = nil

	return &SecureKey{
		enclave: enclave,
		size:    enclave.Size(),
	}, nil
}
