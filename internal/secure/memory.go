package secure

import (
	"errors"
	"sync"
	"sync/atomic"
)

const (
	// DefaultMemoryLimit is the default maximum secure memory (512MB).
	DefaultMemoryLimit = 512 * 1024 * 1024
	// MinMemoryLimit is the minimum allowed memory limit (1MB).
	MinMemoryLimit = 1 * 1024 * 1024
)

var (
	// ErrMemoryLimitExceeded indicates the memory limit has been reached.
	ErrMemoryLimitExceeded = errors.New("secure memory limit exceeded")
	// ErrInvalidMemoryLimit indicates an invalid memory limit was provided.
	ErrInvalidMemoryLimit = errors.New("memory limit must be at least 1MB")
)

// MemoryTracker tracks secure memory allocations and enforces limits.
// It provides visibility into how much secure memory is being used
// and prevents unbounded growth.
type MemoryTracker struct {
	allocated int64
	limit     int64
	mu        sync.RWMutex
}

// NewMemoryTracker creates a new memory tracker with the given limit.
// Use 0 for limit to use the default (512MB).
func NewMemoryTracker(limit int64) (*MemoryTracker, error) {
	if limit == 0 {
		limit = DefaultMemoryLimit
	}
	if limit < MinMemoryLimit {
		return nil, ErrInvalidMemoryLimit
	}

	return &MemoryTracker{
		limit: limit,
	}, nil
}

// Allocate attempts to reserve the given number of bytes.
// Returns an error if the allocation would exceed the limit.
func (m *MemoryTracker) Allocate(size int64) error {
	if size <= 0 {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.allocated+size > m.limit {
		return ErrMemoryLimitExceeded
	}

	m.allocated += size
	return nil
}

// Free releases the given number of bytes.
// Will not go below zero.
func (m *MemoryTracker) Free(size int64) {
	if size <= 0 {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.allocated -= size
	if m.allocated < 0 {
		m.allocated = 0
	}
}

// Allocated returns the current allocated memory in bytes.
func (m *MemoryTracker) Allocated() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.allocated
}

// Limit returns the memory limit in bytes.
func (m *MemoryTracker) Limit() int64 {
	return atomic.LoadInt64(&m.limit)
}

// Available returns the amount of memory available for allocation.
func (m *MemoryTracker) Available() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.limit - m.allocated
}

// UsagePercent returns the percentage of memory used (0-100).
func (m *MemoryTracker) UsagePercent() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.limit == 0 {
		return 0
	}
	return float64(m.allocated) / float64(m.limit) * 100
}

// Reset clears all allocations (use with caution).
func (m *MemoryTracker) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.allocated = 0
}

// Stats returns memory statistics.
type MemoryStats struct {
	Allocated    int64   `json:"allocated"`
	Limit        int64   `json:"limit"`
	Available    int64   `json:"available"`
	UsagePercent float64 `json:"usage_percent"`
}

// Stats returns current memory statistics.
func (m *MemoryTracker) Stats() MemoryStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return MemoryStats{
		Allocated:    m.allocated,
		Limit:        m.limit,
		Available:    m.limit - m.allocated,
		UsagePercent: float64(m.allocated) / float64(m.limit) * 100,
	}
}

// global default tracker for convenience
var defaultTracker *MemoryTracker
var defaultTrackerOnce sync.Once

// DefaultTracker returns the global default memory tracker.
func DefaultTracker() *MemoryTracker {
	defaultTrackerOnce.Do(func() {
		var err error
		defaultTracker, err = NewMemoryTracker(DefaultMemoryLimit)
		if err != nil {
			// This should never happen with default limit
			panic("failed to create default memory tracker: " + err.Error())
		}
	})
	return defaultTracker
}
