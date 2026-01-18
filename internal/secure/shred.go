package secure

import (
	"crypto/rand"
	"io"
	"sync"

	"github.com/awnumar/memguard"
)

// ShredPasses defines the number of overwrite passes for DoD 5220.22-M compliance.
// Pass 1: All zeros (0x00)
// Pass 2: All ones (0xFF)
// Pass 3: Cryptographically secure random data
// Pass 4: memguard secure zero (constant-time)
const ShredPasses = 4

// Shred securely wipes a byte slice using DoD 5220.22-M standard.
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

// ShredBuffer securely wipes a SecureBuffer.
// memguard already performs secure wiping on Destroy(), so we just
// call Destroy() which handles everything safely under its internal locks.
// The buffer is destroyed after this call.
func ShredBuffer(buf *SecureBuffer) {
	if buf == nil {
		return
	}

	// memguard's Destroy() already wipes the buffer securely before freeing.
	// Attempting manual multi-pass overwrites can race with guard page
	// protection and cause segfaults. Just let memguard handle it.
	buf.Destroy()
}

// ShredKey securely wipes a SecureKey.
// The key is destroyed after shredding.
func ShredKey(key *SecureKey) {
	if key == nil || key.IsDestroyed() {
		return
	}
	key.Destroy()
}

// Shredder provides batch secure deletion with tracking.
type Shredder struct {
	mu         sync.Mutex
	buffers    []*SecureBuffer
	keys       []*SecureKey
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

// TrackBuffer adds a SecureBuffer to be shredded later.
func (s *Shredder) TrackBuffer(buf *SecureBuffer) {
	if buf == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buffers = append(s.buffers, buf)
}

// TrackKey adds a SecureKey to be shredded later.
func (s *Shredder) TrackKey(key *SecureKey) {
	if key == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = append(s.keys, key)
}

// TrackRaw adds a raw byte slice to be shredded later.
// Use sparingly - prefer SecureBuffer for sensitive data.
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

	// Shred buffers
	for _, buf := range s.buffers {
		if buf != nil && !buf.IsDestroyed() {
			ShredBuffer(buf)
			count++
		}
	}
	s.buffers = nil

	// Shred keys
	for _, key := range s.keys {
		if key != nil && !key.IsDestroyed() {
			ShredKey(key)
			count++
		}
	}
	s.keys = nil

	// Shred raw slices
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
	return len(s.buffers) + len(s.keys) + len(s.rawSlices)
}
