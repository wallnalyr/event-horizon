// Package secure provides memory-safe primitives for handling secrets.
package secure

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
)

// ErrScatteredDestroyed indicates the scattered buffer has been destroyed.
var ErrScatteredDestroyed = errors.New("scattered buffer has been destroyed")

// DefaultChunkSize is the default size of each scattered chunk.
const DefaultChunkSize = 256

// ScatteredBuffer splits data into chunks scattered across memory.
// Each chunk is stored in a separately allocated slice, making it harder
// for memory forensics to find and reassemble the original data.
// The chunks are stored in a shuffled order, requiring the order map to reassemble.
type ScatteredBuffer struct {
	chunks    [][]byte // Chunks in shuffled order
	order     []int    // order[i] = original position of chunk at index i
	chunkSize int      // Size of each chunk
	totalSize int      // Original data size
	mu        sync.RWMutex
	destroyed bool
}

// NewScatteredBuffer creates a new scattered buffer with the default chunk size.
// The data is split into chunks and scattered. Source data is wiped.
// IMPORTANT: Always call Destroy() when done.
func NewScatteredBuffer(data []byte) (*ScatteredBuffer, error) {
	return NewScatteredBufferWithChunkSize(data, DefaultChunkSize)
}

// NewScatteredBufferWithChunkSize creates a new scattered buffer with a custom chunk size.
// The data is split into chunks and scattered. Source data is wiped.
// IMPORTANT: Always call Destroy() when done.
func NewScatteredBufferWithChunkSize(data []byte, chunkSize int) (*ScatteredBuffer, error) {
	if data == nil {
		return nil, ErrBufferNil
	}
	if len(data) == 0 {
		return nil, ErrBufferEmpty
	}
	if len(data) > MaxBufferSize {
		return nil, ErrBufferTooLarge
	}
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}

	totalSize := len(data)

	// Calculate number of chunks needed
	numChunks := (totalSize + chunkSize - 1) / chunkSize
	if numChunks < 4 {
		// Force at least 4 chunks for better scattering
		chunkSize = (totalSize + 3) / 4
		if chunkSize < 1 {
			chunkSize = 1
		}
		numChunks = (totalSize + chunkSize - 1) / chunkSize
	}

	// Create order array and shuffle it
	// order[i] = original position of chunk that will be stored at index i
	order := make([]int, numChunks)
	for i := range order {
		order[i] = i
	}
	shuffleOrder(order)

	// Allocate chunks in shuffled order
	// Each chunk is separately allocated to scatter across heap
	chunks := make([][]byte, numChunks)
	for i := 0; i < numChunks; i++ {
		origPos := order[i]
		start := origPos * chunkSize
		end := start + chunkSize
		if end > totalSize {
			end = totalSize
		}
		if start >= totalSize {
			// Empty chunk (padding)
			chunks[i] = make([]byte, 0)
		} else {
			chunkData := make([]byte, end-start)
			copy(chunkData, data[start:end])
			chunks[i] = chunkData
		}
	}

	// Wipe source data
	Shred(data)

	return &ScatteredBuffer{
		chunks:    chunks,
		order:     order,
		chunkSize: chunkSize,
		totalSize: totalSize,
	}, nil
}

// shuffleOrder performs Fisher-Yates shuffle on the order slice.
func shuffleOrder(order []int) {
	n := len(order)
	for i := n - 1; i > 0; i-- {
		// Generate random index j where 0 <= j <= i
		var jBytes [8]byte
		if _, err := rand.Read(jBytes[:]); err != nil {
			// Fallback to simple swap on error
			j := i / 2
			order[i], order[j] = order[j], order[i]
			continue
		}
		j := int(binary.LittleEndian.Uint64(jBytes[:]) % uint64(i+1))
		order[i], order[j] = order[j], order[i]
	}
}

// Read reassembles and returns a copy of the data.
// The returned slice should be wiped when no longer needed.
func (sb *ScatteredBuffer) Read() ([]byte, error) {
	sb.mu.RLock()
	defer sb.mu.RUnlock()

	if sb.destroyed {
		return nil, ErrScatteredDestroyed
	}

	// Reassemble data by placing each chunk at its original position
	result := make([]byte, sb.totalSize)

	for i, origPos := range sb.order {
		if i >= len(sb.chunks) {
			continue
		}
		chunk := sb.chunks[i]
		if len(chunk) == 0 {
			continue
		}

		// Calculate where this chunk belongs in the original data
		start := origPos * sb.chunkSize
		if start >= sb.totalSize {
			continue
		}

		// Copy chunk to its original position
		end := start + len(chunk)
		if end > sb.totalSize {
			end = sb.totalSize
		}
		copy(result[start:end], chunk[:end-start])
	}

	return result, nil
}

// Use provides safe access to the buffer contents via a callback.
// The reassembled data is wiped after the callback returns.
func (sb *ScatteredBuffer) Use(fn func(data []byte) error) error {
	data, err := sb.Read()
	if err != nil {
		return err
	}
	defer Shred(data)

	return fn(data)
}

// Size returns the total size of the original data.
func (sb *ScatteredBuffer) Size() int {
	sb.mu.RLock()
	defer sb.mu.RUnlock()

	if sb.destroyed {
		return 0
	}
	return sb.totalSize
}

// ChunkCount returns the number of chunks.
func (sb *ScatteredBuffer) ChunkCount() int {
	sb.mu.RLock()
	defer sb.mu.RUnlock()

	if sb.destroyed {
		return 0
	}
	return len(sb.chunks)
}

// Destroy securely wipes all chunks.
// Safe to call multiple times.
func (sb *ScatteredBuffer) Destroy() {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if sb.destroyed {
		return
	}

	// Shred all chunks
	for i := range sb.chunks {
		if sb.chunks[i] != nil {
			Shred(sb.chunks[i])
			sb.chunks[i] = nil
		}
	}

	sb.chunks = nil
	sb.order = nil
	sb.totalSize = 0
	sb.destroyed = true
}

// IsDestroyed returns whether the buffer has been destroyed.
func (sb *ScatteredBuffer) IsDestroyed() bool {
	sb.mu.RLock()
	defer sb.mu.RUnlock()
	return sb.destroyed
}
