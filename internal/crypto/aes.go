package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"github.com/fileez/fileez/internal/secure"
)

var (
	// ErrInvalidKeySize indicates the key is not 32 bytes (AES-256).
	ErrInvalidKeySize = errors.New("key must be 32 bytes for AES-256")
	// ErrEncryptionFailed indicates encryption failed.
	ErrEncryptionFailed = errors.New("encryption failed")
	// ErrDecryptionFailed indicates decryption failed (likely wrong key or tampered data).
	ErrDecryptionFailed = errors.New("decryption failed: data may be corrupted or key is wrong")
	// ErrCiphertextTooShort indicates the ciphertext is shorter than the nonce.
	ErrCiphertextTooShort = errors.New("ciphertext too short")
)

// Encrypt encrypts plaintext using AES-256-GCM with the provided key.
// The nonce is prepended to the ciphertext.
//
// Returns: nonce (12 bytes) || ciphertext || auth tag (16 bytes)
//
// IMPORTANT: The returned ciphertext should be stored in a SecureBuffer
// if it contains sensitive data.
func Encrypt(key *secure.SecureKey, plaintext []byte) ([]byte, error) {
	if key == nil || key.IsDestroyed() {
		return nil, secure.ErrKeyDestroyed
	}

	// Generate random nonce
	nonceBuf, err := GenerateNonce()
	if err != nil {
		return nil, err
	}
	defer nonceBuf.Destroy()

	var ciphertext []byte

	err = key.Use(func(keyBytes []byte) error {
		if len(keyBytes) != AES256KeySize {
			return ErrInvalidKeySize
		}

		block, err := aes.NewCipher(keyBytes)
		if err != nil {
			return err
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return err
		}

		// Get nonce bytes
		var nonce []byte
		if err := nonceBuf.Use(func(n []byte) error {
			nonce = make([]byte, len(n))
			copy(nonce, n)
			return nil
		}); err != nil {
			return err
		}

		// Encrypt: ciphertext = nonce || encrypted || tag
		ciphertext = gcm.Seal(nonce, nonce, plaintext, nil)
		return nil
	})

	if err != nil {
		return nil, err
	}

	if ciphertext == nil {
		return nil, ErrEncryptionFailed
	}

	return ciphertext, nil
}

// Decrypt decrypts ciphertext that was encrypted with Encrypt().
// Expects format: nonce (12 bytes) || ciphertext || auth tag (16 bytes)
//
// Returns the decrypted plaintext or an error if decryption fails.
func Decrypt(key *secure.SecureKey, ciphertext []byte) ([]byte, error) {
	if key == nil || key.IsDestroyed() {
		return nil, secure.ErrKeyDestroyed
	}

	if len(ciphertext) < NonceBytes+16 { // nonce + minimum auth tag
		return nil, ErrCiphertextTooShort
	}

	var plaintext []byte

	err := key.Use(func(keyBytes []byte) error {
		if len(keyBytes) != AES256KeySize {
			return ErrInvalidKeySize
		}

		block, err := aes.NewCipher(keyBytes)
		if err != nil {
			return err
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return err
		}

		// Extract nonce from beginning of ciphertext
		nonce := ciphertext[:NonceBytes]
		encryptedData := ciphertext[NonceBytes:]

		// Decrypt
		plaintext, err = gcm.Open(nil, nonce, encryptedData, nil)
		if err != nil {
			return ErrDecryptionFailed
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// EncryptSecure encrypts a SecureBuffer and returns the ciphertext.
// The original buffer is not modified.
func EncryptSecure(key *secure.SecureKey, plaintextBuf *secure.SecureBuffer) ([]byte, error) {
	if plaintextBuf == nil || plaintextBuf.IsDestroyed() {
		return nil, secure.ErrBufferDestroyed
	}

	var ciphertext []byte
	var encErr error

	err := plaintextBuf.Use(func(plaintext []byte) error {
		ciphertext, encErr = Encrypt(key, plaintext)
		return encErr
	})

	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

// DecryptSecure decrypts ciphertext into a SecureBuffer.
// IMPORTANT: Caller must call Destroy() on the returned buffer.
func DecryptSecure(key *secure.SecureKey, ciphertext []byte) (*secure.SecureBuffer, error) {
	plaintext, err := Decrypt(key, ciphertext)
	if err != nil {
		return nil, err
	}

	// NewSecureBufferFromBytes already wipes plaintext on success
	buf, err := secure.NewSecureBufferFromBytes(plaintext)
	if err != nil {
		// If buffer creation fails, wipe manually
		secure.Shred(plaintext)
		return nil, err
	}

	return buf, nil
}

// EncryptInPlace encrypts plaintext and shreds the original.
// WARNING: The plaintext slice will be zeroed after encryption.
func EncryptInPlace(key *secure.SecureKey, plaintext []byte) ([]byte, error) {
	ciphertext, err := Encrypt(key, plaintext)

	// Shred plaintext regardless of encryption success
	secure.Shred(plaintext)

	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

// EncryptSecureToSecure encrypts a SecureBuffer and returns ciphertext in a SecureBuffer.
// Use when ciphertext should also be protected in memory.
// IMPORTANT: Caller must call Destroy() on the returned buffer.
func EncryptSecureToSecure(key *secure.SecureKey, plaintextBuf *secure.SecureBuffer) (*secure.SecureBuffer, error) {
	ciphertext, err := EncryptSecure(key, plaintextBuf)
	if err != nil {
		return nil, err
	}

	buf, err := secure.NewSecureBufferFromBytes(ciphertext)
	if err != nil {
		secure.Shred(ciphertext)
		return nil, err
	}

	return buf, nil
}
