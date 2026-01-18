// Package secure provides memory-safe primitives for handling secrets.
package secure

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"sync"
	"time"
)

// Default decoy pool settings
const (
	DefaultDecoyCount   = 50
	DefaultDecoyMinSize = 1024         // 1KB
	DefaultDecoyMaxSize = 512 * 1024   // 512KB
	DecoyRotationInterval = 5 * time.Second
)

// DecoyPool maintains a pool of fake data buffers that look like encrypted data.
// This creates noise in memory, making it harder for attackers to identify
// which memory regions contain real data vs decoys.
type DecoyPool struct {
	mu       sync.RWMutex
	decoys   [][]byte
	done     chan struct{}
	minSize  int
	maxSize  int
	count    int
	started  bool
}

var (
	globalDecoyPool     *DecoyPool
	globalDecoyPoolOnce sync.Once
	globalDecoyPoolMu   sync.Mutex
)

// GlobalDecoyPool returns the global decoy pool singleton.
// Returns nil if InitDecoyPool hasn't been called.
func GlobalDecoyPool() *DecoyPool {
	globalDecoyPoolMu.Lock()
	defer globalDecoyPoolMu.Unlock()
	return globalDecoyPool
}

// InitDecoyPool initializes the global decoy pool with custom settings.
// Should be called once at application startup.
// Safe to call multiple times - subsequent calls are no-ops.
func InitDecoyPool(count, minSize, maxSize int) {
	globalDecoyPoolOnce.Do(func() {
		globalDecoyPoolMu.Lock()
		defer globalDecoyPoolMu.Unlock()

		globalDecoyPool = NewDecoyPool(count, minSize, maxSize)
		globalDecoyPool.Start()
	})
}

// NewDecoyPool creates a new decoy pool.
// Call Start() to begin allocation and rotation.
func NewDecoyPool(count, minSize, maxSize int) *DecoyPool {
	if count <= 0 {
		count = DefaultDecoyCount
	}
	if minSize <= 0 {
		minSize = DefaultDecoyMinSize
	}
	if maxSize <= 0 {
		maxSize = DefaultDecoyMaxSize
	}
	if minSize > maxSize {
		minSize = maxSize
	}

	return &DecoyPool{
		done:    make(chan struct{}),
		minSize: minSize,
		maxSize: maxSize,
		count:   count,
	}
}

// Start allocates decoys and begins the rotation loop.
// Safe to call multiple times.
func (p *DecoyPool) Start() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.started {
		return
	}

	p.started = true
	p.allocateDecoys(p.count)
	go p.rotateLoop()
}

// allocateDecoys creates the initial pool of decoy buffers.
// Must be called with lock held.
func (p *DecoyPool) allocateDecoys(count int) {
	p.decoys = make([][]byte, count)
	for i := 0; i < count; i++ {
		size := p.randomSize()
		decoy := make([]byte, size)
		// Fill with random data to look like encrypted content
		io.ReadFull(rand.Reader, decoy)
		p.decoys[i] = decoy
	}
}

// rotateLoop periodically replaces random decoys with new ones.
func (p *DecoyPool) rotateLoop() {
	ticker := time.NewTicker(DecoyRotationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.rotateRandom()
		case <-p.done:
			return
		}
	}
}

// rotateRandom replaces a random decoy with a new one.
func (p *DecoyPool) rotateRandom() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.decoys) == 0 {
		return
	}

	// Pick random index
	var idxBytes [8]byte
	if _, err := rand.Read(idxBytes[:]); err != nil {
		return
	}
	idx := int(binary.LittleEndian.Uint64(idxBytes[:]) % uint64(len(p.decoys)))

	// Shred old decoy
	if p.decoys[idx] != nil {
		Shred(p.decoys[idx])
	}

	// Create new decoy with random size
	size := p.randomSize()
	newDecoy := make([]byte, size)
	io.ReadFull(rand.Reader, newDecoy)
	p.decoys[idx] = newDecoy
}

// randomSize returns a random size between minSize and maxSize.
func (p *DecoyPool) randomSize() int {
	if p.maxSize <= p.minSize {
		return p.minSize
	}

	var sizeBytes [8]byte
	if _, err := rand.Read(sizeBytes[:]); err != nil {
		return p.minSize
	}

	sizeRange := uint64(p.maxSize - p.minSize)
	randomOffset := binary.LittleEndian.Uint64(sizeBytes[:]) % sizeRange
	return p.minSize + int(randomOffset)
}

// Count returns the number of decoys in the pool.
func (p *DecoyPool) Count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.decoys)
}

// TotalSize returns the total memory used by all decoys.
func (p *DecoyPool) TotalSize() int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	total := 0
	for _, d := range p.decoys {
		total += len(d)
	}
	return total
}

// Destroy stops rotation and shreds all decoys.
// Safe to call multiple times.
func (p *DecoyPool) Destroy() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.started {
		return
	}

	// Stop rotation
	select {
	case <-p.done:
		// Already stopped
	default:
		close(p.done)
	}

	// Shred all decoys
	for i := range p.decoys {
		if p.decoys[i] != nil {
			Shred(p.decoys[i])
			p.decoys[i] = nil
		}
	}
	p.decoys = nil
}
