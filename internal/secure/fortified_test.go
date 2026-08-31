package secure

import (
	"bytes"
	"runtime"
	"testing"
	"time"
)

func TestBoundedChunkingCapsChunkCount(t *testing.T) {
	cases := []int{1, 255, 256, 1024, 1 << 20, 60 << 20, 100 << 20}
	for _, size := range cases {
		chunkSize, numChunks := boundedChunking(size, DefaultChunkSize)
		if numChunks > MaxScatterChunks {
			t.Fatalf("size=%d: numChunks=%d exceeds cap %d", size, numChunks, MaxScatterChunks)
		}
		if chunkSize <= 0 {
			t.Fatalf("size=%d: non-positive chunkSize %d", size, chunkSize)
		}
		// The chunks must be able to cover the whole payload.
		if chunkSize*numChunks < size {
			t.Fatalf("size=%d: chunkSize*numChunks=%d < size", size, chunkSize*numChunks)
		}
		// Small payloads should still be split for scattering (unless tiny).
		if size >= 4 && numChunks < 4 {
			t.Fatalf("size=%d: expected >=4 chunks, got %d", size, numChunks)
		}
	}
}

func TestRotationIntervalScalesWithSize(t *testing.T) {
	// Small payloads keep the fast base interval.
	if got := rotationIntervalFor(1024, DefaultRotationInterval); got != DefaultRotationInterval {
		t.Fatalf("small payload: got %v, want %v", got, DefaultRotationInterval)
	}
	// Large payloads slow down but never below base and never above the ceiling.
	big := rotationIntervalFor(60<<20, DefaultRotationInterval)
	if big <= DefaultRotationInterval {
		t.Fatalf("large payload should slow rotation, got %v", big)
	}
	if big > maxRotationInterval {
		t.Fatalf("rotation interval %v exceeds ceiling %v", big, maxRotationInterval)
	}
	if huge := rotationIntervalFor(1<<40, DefaultRotationInterval); huge != maxRotationInterval {
		t.Fatalf("huge payload should clamp to ceiling %v, got %v", maxRotationInterval, huge)
	}
}

func TestFortifiedBufferRoundTrip(t *testing.T) {
	for _, size := range []int{1, 200, 4096, 300000} {
		data := bytes.Repeat([]byte{0xAB, 0x01, 0x7F, 0xC3}, size/4+1)[:size]
		want := append([]byte(nil), data...)

		fb, err := NewFortifiedBuffer(data)
		if err != nil {
			t.Fatalf("size=%d: NewFortifiedBuffer: %v", size, err)
		}
		got, err := fb.Read()
		if err != nil {
			t.Fatalf("size=%d: Read: %v", size, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("size=%d: round-trip mismatch", size)
		}
		fb.Destroy()
		if _, err := fb.Read(); err == nil {
			t.Fatalf("size=%d: Read after Destroy should error", size)
		}
	}
}

// TestFortifiedBufferGoroutineBounded guards the CRITICAL fix: a large payload
// must not spawn one goroutine per 256-byte chunk.
func TestFortifiedBufferGoroutineBounded(t *testing.T) {
	before := runtime.NumGoroutine()
	fb, err := NewFortifiedBuffer(bytes.Repeat([]byte{0x5A}, 8<<20)) // 8MB
	if err != nil {
		t.Fatalf("NewFortifiedBuffer: %v", err)
	}
	defer fb.Destroy()
	// Allow rotation goroutines to start.
	time.Sleep(50 * time.Millisecond)
	delta := runtime.NumGoroutine() - before
	// With the pre-fix 256-byte chunking, 8MB would create ~32,768 goroutines.
	if delta > MaxScatterChunks+8 {
		t.Fatalf("8MB payload spawned %d goroutines; expected <= %d", delta, MaxScatterChunks+8)
	}
}
