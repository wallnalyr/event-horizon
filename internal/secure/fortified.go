// Package secure provides memory-safe primitives for handling secrets.
package secure

import (
	"errors"
	"sync"
	"time"
)

// ErrFortifiedDestroyed indicates the fortified buffer has been destroyed.
var ErrFortifiedDestroyed = errors.New("fortified buffer has been destroyed")

// FortifiedOptions configures the protection layers of a FortifiedBuffer.
type FortifiedOptions struct {
	// UseObfuscation enables rotating XOR pad obfuscation.
	// Default: true
	UseObfuscation bool

	// UseScatter enables scattered chunk storage.
	// Default: true
	UseScatter bool

	// RegisterTripwire registers this buffer for auto-destruction on intrusion.
	// Default: true
	RegisterTripwire bool

	// RotationInterval is the XOR pad rotation interval.
	// Default: 100ms
	RotationInterval time.Duration

	// ChunkSize is the size of scattered chunks.
	// Default: 256 bytes
	ChunkSize int
}

// DefaultFortifiedOptions returns the default configuration with all protections enabled.
func DefaultFortifiedOptions() FortifiedOptions {
	return FortifiedOptions{
		UseObfuscation:   true,
		UseScatter:       true,
		RegisterTripwire: true,
		RotationInterval: DefaultRotationInterval,
		ChunkSize:        DefaultChunkSize,
	}
}

// FortifiedBuffer combines multiple memory protection techniques:
// 1. Scatter storage - data split into randomly ordered chunks
// 2. XOR obfuscation - data XOR'd with a rotating pad
// 3. Tripwire registration - auto-destroy on debugger detection
//
// Data flows: input -> scatter -> obfuscate each chunk
// On read: de-obfuscate chunks -> reassemble
type FortifiedBuffer struct {
	// Either scattered+obfuscated OR just obfuscated
	obfuscatedChunks []*ObfuscatedBuffer // Obfuscated chunks (when scatter enabled)
	obfuscated       *ObfuscatedBuffer   // Single obfuscated buffer (when scatter disabled)
	scattered        *ScatteredBuffer    // For tracking chunk order (when scatter enabled)

	chunkOrder []int // chunkOrder[i] = original position of chunk at index i
	chunkSize  int   // Size of each chunk (for reassembly)
	totalSize  int

	mu        sync.RWMutex
	destroyed bool

	useObfuscation bool
	useScatter     bool
}

// NewFortifiedBuffer creates a new fortified buffer with default options.
// The data is protected with all available techniques and the source is wiped.
// IMPORTANT: Always call Destroy() when done.
func NewFortifiedBuffer(data []byte) (*FortifiedBuffer, error) {
	return NewFortifiedBufferWithOptions(data, DefaultFortifiedOptions())
}

// NewFortifiedBufferWithOptions creates a new fortified buffer with custom options.
// The data is protected according to the specified options and the source is wiped.
// IMPORTANT: Always call Destroy() when done.
func NewFortifiedBufferWithOptions(data []byte, opts FortifiedOptions) (*FortifiedBuffer, error) {
	if data == nil {
		return nil, ErrBufferNil
	}
	if len(data) == 0 {
		return nil, ErrBufferEmpty
	}
	if len(data) > MaxBufferSize {
		return nil, ErrBufferTooLarge
	}

	fb := &FortifiedBuffer{
		totalSize:      len(data),
		useObfuscation: opts.UseObfuscation,
		useScatter:     opts.UseScatter,
	}

	var err error

	if opts.UseScatter && opts.UseObfuscation {
		// Both scatter and obfuscate: scatter first, then obfuscate each chunk
		err = fb.initScatterObfuscate(data, opts)
	} else if opts.UseObfuscation {
		// Just obfuscate (no scatter)
		fb.obfuscated, err = NewObfuscatedBufferWithInterval(data, opts.RotationInterval)
	} else if opts.UseScatter {
		// Just scatter (no obfuscation) - use scattered buffer for storage
		// Create temporary scattered buffer to get the chunks
		sb, sbErr := NewScatteredBufferWithChunkSize(data, opts.ChunkSize)
		if sbErr != nil {
			return nil, sbErr
		}
		fb.scattered = sb
	} else {
		// No protection - just obfuscate minimally
		fb.obfuscated, err = NewObfuscatedBufferWithInterval(data, opts.RotationInterval)
	}

	if err != nil {
		return nil, err
	}

	// Register with tripwire for auto-destruction
	if opts.RegisterTripwire {
		GlobalTripwire().RegisterCallback(func() {
			fb.Destroy()
		})
	}

	return fb, nil
}

// initScatterObfuscate splits data into chunks in shuffled order, then obfuscates each chunk.
// chunkOrder[i] = original position of the chunk stored at index i
func (fb *FortifiedBuffer) initScatterObfuscate(data []byte, opts FortifiedOptions) error {
	chunkSize := opts.ChunkSize
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}

	totalSize := len(data)

	// Calculate number of chunks
	numChunks := (totalSize + chunkSize - 1) / chunkSize
	if numChunks < 4 {
		chunkSize = (totalSize + 3) / 4
		if chunkSize < 1 {
			chunkSize = 1
		}
		numChunks = (totalSize + chunkSize - 1) / chunkSize
	}

	// Store chunkSize for reassembly
	fb.chunkSize = chunkSize

	// Create shuffled order: chunkOrder[i] = original position of chunk at index i
	fb.chunkOrder = make([]int, numChunks)
	for i := range fb.chunkOrder {
		fb.chunkOrder[i] = i
	}
	shuffleOrder(fb.chunkOrder)

	// Create obfuscated buffer for each chunk, stored in shuffled order
	fb.obfuscatedChunks = make([]*ObfuscatedBuffer, numChunks)

	for i := 0; i < numChunks; i++ {
		// Get the original position for this shuffled index
		origPos := fb.chunkOrder[i]
		start := origPos * chunkSize
		end := start + chunkSize
		if end > totalSize {
			end = totalSize
		}

		var chunkData []byte
		if start >= totalSize {
			chunkData = []byte{} // Empty chunk
		} else {
			chunkData = make([]byte, end-start)
			copy(chunkData, data[start:end])
		}

		// Handle empty chunks with a minimal placeholder
		if len(chunkData) == 0 {
			chunkData = []byte{0}
		}

		ob, err := NewObfuscatedBufferWithInterval(chunkData, opts.RotationInterval)
		if err != nil {
			// Cleanup already created chunks
			for j := 0; j < i; j++ {
				if fb.obfuscatedChunks[j] != nil {
					fb.obfuscatedChunks[j].Destroy()
				}
			}
			Shred(data)
			return err
		}

		fb.obfuscatedChunks[i] = ob
	}

	// Wipe source data
	Shred(data)

	return nil
}

// Read decrypts, reassembles, and returns a copy of the data.
// The returned slice should be wiped when no longer needed.
func (fb *FortifiedBuffer) Read() ([]byte, error) {
	fb.mu.RLock()
	defer fb.mu.RUnlock()

	if fb.destroyed {
		return nil, ErrFortifiedDestroyed
	}

	if fb.obfuscatedChunks != nil {
		// Scatter + obfuscate mode: reassemble from obfuscated chunks
		return fb.readScatterObfuscate()
	} else if fb.obfuscated != nil {
		// Single obfuscated buffer
		return fb.obfuscated.Read()
	} else if fb.scattered != nil {
		// Just scattered
		return fb.scattered.Read()
	}

	return nil, ErrFortifiedDestroyed
}

// readScatterObfuscate reassembles data from obfuscated chunks.
// Each chunk is placed at its original position (chunkOrder[i] * chunkSize).
func (fb *FortifiedBuffer) readScatterObfuscate() ([]byte, error) {
	result := make([]byte, fb.totalSize)

	for i, origPos := range fb.chunkOrder {
		if i >= len(fb.obfuscatedChunks) {
			continue
		}

		chunk := fb.obfuscatedChunks[i]
		if chunk == nil {
			continue
		}

		chunkData, err := chunk.Read()
		if err != nil {
			Shred(result)
			return nil, err
		}

		// Calculate where this chunk belongs in the original data
		start := origPos * fb.chunkSize
		if start >= fb.totalSize {
			Shred(chunkData)
			continue
		}

		// Skip placeholder chunks (single zero byte for empty positions)
		if len(chunkData) == 1 && chunkData[0] == 0 && start >= fb.totalSize {
			Shred(chunkData)
			continue
		}

		// Copy chunk to its original position
		end := start + len(chunkData)
		if end > fb.totalSize {
			end = fb.totalSize
		}
		copyLen := end - start
		if copyLen > 0 && copyLen <= len(chunkData) {
			copy(result[start:end], chunkData[:copyLen])
		}

		Shred(chunkData)
	}

	return result, nil
}

// Use provides safe access to the buffer contents via a callback.
// The decrypted data is wiped after the callback returns.
func (fb *FortifiedBuffer) Use(fn func(data []byte) error) error {
	data, err := fb.Read()
	if err != nil {
		return err
	}
	defer Shred(data)

	return fn(data)
}

// Size returns the size of the original data.
func (fb *FortifiedBuffer) Size() int {
	fb.mu.RLock()
	defer fb.mu.RUnlock()

	if fb.destroyed {
		return 0
	}
	return fb.totalSize
}

// Destroy securely wipes all data and stops all rotation goroutines.
// Safe to call multiple times.
func (fb *FortifiedBuffer) Destroy() {
	fb.mu.Lock()
	defer fb.mu.Unlock()

	if fb.destroyed {
		return
	}

	// Destroy obfuscated chunks
	if fb.obfuscatedChunks != nil {
		for i := range fb.obfuscatedChunks {
			if fb.obfuscatedChunks[i] != nil {
				fb.obfuscatedChunks[i].Destroy()
				fb.obfuscatedChunks[i] = nil
			}
		}
		fb.obfuscatedChunks = nil
	}

	// Destroy single obfuscated buffer
	if fb.obfuscated != nil {
		fb.obfuscated.Destroy()
		fb.obfuscated = nil
	}

	// Destroy scattered buffer
	if fb.scattered != nil {
		fb.scattered.Destroy()
		fb.scattered = nil
	}

	fb.chunkOrder = nil
	fb.chunkSize = 0
	fb.totalSize = 0
	fb.destroyed = true
}

// IsDestroyed returns whether the buffer has been destroyed.
func (fb *FortifiedBuffer) IsDestroyed() bool {
	fb.mu.RLock()
	defer fb.mu.RUnlock()
	return fb.destroyed
}

// ShredFortifiedBuffer performs DoD 5220.22-M compliant shredding on a FortifiedBuffer.
func ShredFortifiedBuffer(buf *FortifiedBuffer) {
	if buf != nil {
		buf.Destroy()
	}
}
