package secure

import (
	"crypto/subtle"
	"errors"
	"sync"

	"github.com/awnumar/memguard"
)

const MaxKeySize = 64 // 512-bit maximum

var (
	// ErrKeyDestroyed indicates the key has been securely wiped.
	ErrKeyDestroyed = errors.New("secure key has been destroyed")
	// ErrKeyNil indicates a nil key was provided.
	ErrKeyNil = errors.New("key data cannot be nil")
	// ErrKeyTooLarge indicates the key exceeds maximum allowed size.
	ErrKeyTooLarge = errors.New("key exceeds maximum size (64 bytes)")
)

// SecureKey wraps memguard.Enclave for secure key storage.
// The key is ENCRYPTED in RAM when not in use, providing protection
// against memory dumps, cold boot attacks, and debugging.
//
// CRITICAL: Never store the key bytes outside the Use() callback.
// The key is only decrypted temporarily during Use() and immediately
// re-encrypted when the callback returns.
//
// Example:
//
//	key, _ := NewSecureKey(derivedKeyBytes)
//	defer key.Destroy()
//
//	err := key.Use(func(keyBytes []byte) error {
//	    // Perform crypto operation with keyBytes
//	    return aesGCM.Seal(nonce, plaintext, nil)
//	})
type SecureKey struct {
	enclave   *memguard.Enclave
	size      int
	destroyed bool
	mu        sync.Mutex
}

// NewSecureKey creates a new SecureKey from the given key bytes.
// The source bytes are automatically zeroed after creating the enclave.
// IMPORTANT: Always call Destroy() when done, preferably via defer.
//
// The key is immediately encrypted in memory after creation.
func NewSecureKey(keyData []byte) (*SecureKey, error) {
	if keyData == nil || len(keyData) == 0 {
		return nil, ErrKeyNil
	}
	if len(keyData) > MaxKeySize {
		return nil, ErrKeyTooLarge
	}

	// Create enclave (key is encrypted in memory)
	enclave := memguard.NewEnclave(keyData)
	if enclave == nil {
		return nil, errors.New("failed to create secure enclave")
	}

	// Zero source immediately - don't rely on caller
	memguard.WipeBytes(keyData)

	return &SecureKey{
		enclave: enclave,
		size:    len(keyData),
	}, nil
}

// NewSecureKeyFromBuffer creates a SecureKey from a SecureBuffer.
// The buffer is destroyed in the process (converted to enclave).
// This is more secure than NewSecureKey as the plaintext key
// never exists in unprotected memory.
func NewSecureKeyFromBuffer(buf *SecureBuffer) (*SecureKey, error) {
	if buf == nil {
		return nil, ErrBufferNil
	}
	return buf.Seal()
}

// Size returns the size of the key in bytes.
func (k *SecureKey) Size() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.size
}

// Use provides temporary access to the decrypted key via a callback.
// This is the ONLY way to access the key bytes.
//
// The key is:
// 1. Decrypted into a locked buffer
// 2. Passed to the callback
// 3. Securely wiped and re-encrypted when callback returns
//
// CRITICAL: Never store or copy keyBytes outside this callback.
// Any such storage is a security violation.
//
// Example:
//
//	err := key.Use(func(keyBytes []byte) error {
//	    block, err := aes.NewCipher(keyBytes)
//	    if err != nil {
//	        return err
//	    }
//	    // Use block for encryption/decryption
//	    return nil
//	})
func (k *SecureKey) Use(fn func(key []byte) error) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.destroyed {
		return ErrKeyDestroyed
	}

	// Decrypt key into locked buffer
	buf, err := k.enclave.Open()
	if err != nil {
		return err
	}
	// Destroy buffer when done (re-seals to new enclave internally)
	defer buf.Destroy()

	// Execute callback with decrypted key
	return fn(buf.Bytes())
}

// Destroy securely wipes the encrypted key from memory.
// After calling Destroy, the key cannot be used.
// Safe to call multiple times.
func (k *SecureKey) Destroy() {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.destroyed || k.enclave == nil {
		return
	}

	// Open and destroy to ensure secure wipe.
	// Note: if Open() fails due to memory pressure, enclave memory
	// may not be explicitly zeroed but will be freed by GC.
	if buf, err := k.enclave.Open(); err == nil {
		buf.Destroy()
	}

	k.destroyed = true
	k.enclave = nil
	k.size = 0
}

// IsDestroyed returns whether the key has been destroyed.
func (k *SecureKey) IsDestroyed() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.destroyed
}

// Clone creates a copy of this SecureKey.
// The new key is independent and must be destroyed separately.
func (k *SecureKey) Clone() (*SecureKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.destroyed {
		return nil, ErrKeyDestroyed
	}

	// Open enclave to get key bytes
	buf, err := k.enclave.Open()
	if err != nil {
		return nil, err
	}
	defer buf.Destroy()

	// Create new enclave with copy of key
	newEnclave := memguard.NewEnclave(buf.Bytes())
	if newEnclave == nil {
		return nil, errors.New("failed to clone secure key")
	}

	return &SecureKey{
		enclave: newEnclave,
		size:    k.size,
	}, nil
}

// Equal performs constant-time comparison with another SecureKey.
// Returns false if either key is destroyed or sizes differ.
// Uses crypto/subtle.ConstantTimeCompare to prevent timing attacks.
func (k *SecureKey) Equal(other *SecureKey) (bool, error) {
	if other == nil {
		return false, ErrKeyNil
	}
	// Same key is always equal to itself (also avoids mutex deadlock)
	if k == other {
		return true, nil
	}
	if k.IsDestroyed() || other.IsDestroyed() {
		return false, ErrKeyDestroyed
	}
	if k.Size() != other.Size() {
		return false, nil
	}

	var equal bool
	err := k.Use(func(a []byte) error {
		return other.Use(func(b []byte) error {
			equal = subtle.ConstantTimeCompare(a, b) == 1
			return nil
		})
	})
	return equal, err
}
