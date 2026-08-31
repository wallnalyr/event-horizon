// Package secure provides memory-safe primitives for handling secrets.
package secure

import "errors"

// MaxBufferSize is the maximum size of a fortified/obfuscated/scattered buffer.
const MaxBufferSize = 100 * 1024 * 1024 // 100MB maximum

var (
	// ErrBufferNil indicates a nil buffer was provided.
	ErrBufferNil = errors.New("buffer cannot be nil")
	// ErrBufferTooLarge indicates the buffer exceeds maximum allowed size.
	ErrBufferTooLarge = errors.New("buffer exceeds maximum size (100MB)")
	// ErrBufferEmpty indicates an empty buffer was provided.
	ErrBufferEmpty = errors.New("buffer cannot be empty")
)
