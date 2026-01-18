// Package secure provides memory-safe primitives for handling secrets.
package secure

import (
	"sync"
	"time"
)

// DefaultTripwireInterval is how often the tripwire checks for intrusion.
const DefaultTripwireInterval = 50 * time.Millisecond

// TripwireCallback is called when intrusion is detected.
type TripwireCallback func()

// Tripwire monitors for debugging/intrusion attempts and triggers callbacks.
// When an intrusion is detected (e.g., debugger attached), all registered
// callbacks are invoked to allow immediate data destruction.
type Tripwire struct {
	mu        sync.Mutex
	callbacks []TripwireCallback
	done      chan struct{}
	triggered bool
	interval  time.Duration
	started   bool
}

var (
	globalTripwire     *Tripwire
	globalTripwireOnce sync.Once
)

// GlobalTripwire returns the global tripwire singleton.
// The tripwire is automatically started on first access.
func GlobalTripwire() *Tripwire {
	globalTripwireOnce.Do(func() {
		globalTripwire = NewTripwire()
		globalTripwire.Start()
	})
	return globalTripwire
}

// NewTripwire creates a new tripwire with default settings.
// Call Start() to begin monitoring.
func NewTripwire() *Tripwire {
	return NewTripwireWithInterval(DefaultTripwireInterval)
}

// NewTripwireWithInterval creates a new tripwire with a custom check interval.
// Call Start() to begin monitoring.
func NewTripwireWithInterval(interval time.Duration) *Tripwire {
	if interval <= 0 {
		interval = DefaultTripwireInterval
	}
	return &Tripwire{
		done:     make(chan struct{}),
		interval: interval,
	}
}

// Start begins the intrusion detection monitoring.
// Safe to call multiple times.
func (t *Tripwire) Start() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.started {
		return
	}

	t.started = true
	go t.watchLoop()
}

// RegisterCallback adds a callback to be invoked on intrusion detection.
// Callbacks are invoked in the order they were registered.
func (t *Tripwire) RegisterCallback(fn TripwireCallback) {
	if fn == nil {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.triggered {
		// Already triggered, invoke immediately
		go fn()
		return
	}

	t.callbacks = append(t.callbacks, fn)
}

// ManualTrigger manually triggers the tripwire for testing purposes.
func (t *Tripwire) ManualTrigger() {
	t.trigger()
}

// IsTriggered returns whether the tripwire has been triggered.
func (t *Tripwire) IsTriggered() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.triggered
}

// Stop halts the monitoring goroutine.
// Safe to call multiple times.
func (t *Tripwire) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.started {
		return
	}

	select {
	case <-t.done:
		// Already stopped
	default:
		close(t.done)
	}
}

// watchLoop continuously checks for intrusion.
func (t *Tripwire) watchLoop() {
	ticker := time.NewTicker(t.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if detectIntrusion() {
				t.trigger()
				return // Stop monitoring after trigger
			}
		case <-t.done:
			return
		}
	}
}

// trigger invokes all registered callbacks.
func (t *Tripwire) trigger() {
	t.mu.Lock()

	if t.triggered {
		t.mu.Unlock()
		return
	}
	t.triggered = true

	// Copy callbacks to avoid holding lock during execution
	callbacks := make([]TripwireCallback, len(t.callbacks))
	copy(callbacks, t.callbacks)

	t.mu.Unlock()

	// Invoke all callbacks
	for _, cb := range callbacks {
		if cb != nil {
			cb()
		}
	}
}
