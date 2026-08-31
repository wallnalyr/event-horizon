package secure

import (
	"crypto/rand"
	"io"
	"sync"

	"github.com/awnumar/memguard"
)

// ShredPasses defines the number of overwrite passes for the multi-pass wipe.
// Pass 1: All zeros (0x00)
// Pass 2: All ones (0xFF)
// Pass 3: Cryptographically secure random data
// Pass 4: memguard secure zero (constant-time)
const ShredPasses = 4

// Shred securely wipes a byte slice with a multi-pass overwrite, in place.
// After shredding, the slice will contain zeros.
//
// WARNING: This operates on the original slice in place.
// Make sure the slice is not referenced elsewhere before shredding.
func Shred(data []byte) {
	if len(data) == 0 {
		return
	}

	// Pass 1: Overwrite with zeros
	for i := range data {
		data[i] = 0x00
	}

	// Pass 2: Overwrite with ones
	for i := range data {
		data[i] = 0xFF
	}

	// Pass 3: Overwrite with cryptographically secure random data
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		// If random fails, use deterministic pattern as fallback
		for i := range data {
			data[i] = byte(i ^ 0xAA)
		}
	}

	// Pass 4: Final secure zeroing using memguard (constant-time)
	memguard.WipeBytes(data)
}

// Shredder provides batch secure deletion of raw byte slices.
type Shredder struct {
	mu         sync.Mutex
	rawSlices  [][]byte
	onShredded func(count int)
}

// NewShredder creates a new Shredder instance.
// The optional callback is invoked after each ShredAll with the count of items shredded.
func NewShredder(onShredded func(count int)) *Shredder {
	return &Shredder{
		onShredded: onShredded,
	}
}

// TrackRaw adds a raw byte slice to be shredded later.
func (s *Shredder) TrackRaw(data []byte) {
	if len(data) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rawSlices = append(s.rawSlices, data)
}

// ShredAll securely wipes all tracked items.
// Returns the number of items shredded.
func (s *Shredder) ShredAll() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for _, data := range s.rawSlices {
		if len(data) > 0 {
			Shred(data)
			count++
		}
	}
	s.rawSlices = nil

	if s.onShredded != nil && count > 0 {
		s.onShredded(count)
	}

	return count
}

// Count returns the number of items currently tracked.
func (s *Shredder) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.rawSlices)
}
