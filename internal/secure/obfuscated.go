// Package secure provides memory-safe primitives for handling secrets.
package secure

import (
	"crypto/rand"
	"errors"
	"io"
	"sync"
	"time"
)

// ErrObfuscatedDestroyed indicates the obfuscated buffer has been destroyed.
var ErrObfuscatedDestroyed = errors.New("obfuscated buffer has been destroyed")

// DefaultRotationInterval is the default interval for XOR pad rotation.
const DefaultRotationInterval = 100 * time.Millisecond

// ObfuscatedBuffer stores data XOR'd with a randomly rotating pad.
// The pad rotates on a configurable interval, so an attacker doing memory
// forensics has only a small window to capture both data and pad.
type ObfuscatedBuffer struct {
	data      []byte        // XOR'd data
	pad       []byte        // Current XOR pad
	size      int           // Original data size
	mu        sync.RWMutex  // Protects all fields
	done      chan struct{} // Signals rotation goroutine to stop
	interval  time.Duration // Rotation interval
	destroyed bool          // Whether buffer has been destroyed
}

// NewObfuscatedBuffer creates a new obfuscated buffer with the default rotation interval.
// The data is immediately XOR'd with a random pad and the source is wiped.
// IMPORTANT: Always call Destroy() when done.
func NewObfuscatedBuffer(data []byte) (*ObfuscatedBuffer, error) {
	return NewObfuscatedBufferWithInterval(data, DefaultRotationInterval)
}

// NewObfuscatedBufferWithInterval creates a new obfuscated buffer with a custom rotation interval.
// The data is immediately XOR'd with a random pad and the source is wiped.
// IMPORTANT: Always call Destroy() when done.
func NewObfuscatedBufferWithInterval(data []byte, interval time.Duration) (*ObfuscatedBuffer, error) {
	if data == nil {
		return nil, ErrBufferNil
	}
	if len(data) == 0 {
		return nil, ErrBufferEmpty
	}
	if len(data) > MaxBufferSize {
		return nil, ErrBufferTooLarge
	}
	if interval <= 0 {
		interval = DefaultRotationInterval
	}

	size := len(data)

	// Generate initial XOR pad
	pad := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, pad); err != nil {
		return nil, err
	}

	// XOR data with pad
	xored := make([]byte, size)
	for i := 0; i < size; i++ {
		xored[i] = data[i] ^ pad[i]
	}

	// Wipe source data
	Shred(data)

	ob := &ObfuscatedBuffer{
		data:     xored,
		pad:      pad,
		size:     size,
		done:     make(chan struct{}),
		interval: interval,
	}

	// Start rotation goroutine
	go ob.rotateLoop()

	return ob, nil
}

// rotateLoop continuously rotates the XOR pad at the configured interval.
func (ob *ObfuscatedBuffer) rotateLoop() {
	ticker := time.NewTicker(ob.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ob.rotate()
		case <-ob.done:
			return
		}
	}
}

// rotate generates a new XOR pad and re-XORs the data.
func (ob *ObfuscatedBuffer) rotate() {
	ob.mu.Lock()
	defer ob.mu.Unlock()

	if ob.destroyed {
		return
	}

	// Generate new pad
	newPad := make([]byte, ob.size)
	if _, err := io.ReadFull(rand.Reader, newPad); err != nil {
		// On error, keep current pad
		return
	}

	// Decrypt current data (XOR with old pad) and re-encrypt with new pad
	for i := 0; i < ob.size; i++ {
		plaintext := ob.data[i] ^ ob.pad[i]
		ob.data[i] = plaintext ^ newPad[i]
	}

	// Shred old pad and replace with new
	Shred(ob.pad)
	ob.pad = newPad
}

// Read decrypts and returns a copy of the data.
// The returned slice should be wiped when no longer needed.
func (ob *ObfuscatedBuffer) Read() ([]byte, error) {
	ob.mu.RLock()
	defer ob.mu.RUnlock()

	if ob.destroyed {
		return nil, ErrObfuscatedDestroyed
	}

	// Decrypt data
	result := make([]byte, ob.size)
	for i := 0; i < ob.size; i++ {
		result[i] = ob.data[i] ^ ob.pad[i]
	}

	return result, nil
}

// Use provides safe access to the buffer contents via a callback.
// The decrypted data is wiped after the callback returns.
func (ob *ObfuscatedBuffer) Use(fn func(data []byte) error) error {
	data, err := ob.Read()
	if err != nil {
		return err
	}
	defer Shred(data)

	return fn(data)
}

// Size returns the size of the buffer in bytes.
func (ob *ObfuscatedBuffer) Size() int {
	ob.mu.RLock()
	defer ob.mu.RUnlock()

	if ob.destroyed {
		return 0
	}
	return ob.size
}

// Destroy stops rotation and securely wipes all data.
// Safe to call multiple times.
func (ob *ObfuscatedBuffer) Destroy() {
	ob.mu.Lock()
	defer ob.mu.Unlock()

	if ob.destroyed {
		return
	}

	// Stop rotation goroutine
	close(ob.done)

	// Shred data and pad
	if ob.data != nil {
		Shred(ob.data)
		ob.data = nil
	}
	if ob.pad != nil {
		Shred(ob.pad)
		ob.pad = nil
	}

	ob.size = 0
	ob.destroyed = true
}

// IsDestroyed returns whether the buffer has been destroyed.
func (ob *ObfuscatedBuffer) IsDestroyed() bool {
	ob.mu.RLock()
	defer ob.mu.RUnlock()
	return ob.destroyed
}
