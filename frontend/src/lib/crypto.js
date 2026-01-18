/**
 * Client-side cryptographic utilities for E2EE.
 * Uses Web Crypto API for all operations.
 *
 * Security model:
 * - Password: Never sent to server, wiped after use
 * - Encryption key: Derived client-side, never sent to server, wiped after use
 * - Key hash: SHA-256 of derived key, sent to server for verification only
 * - Salt: Random 16 bytes, sent to server for key derivation on unlock
 */

const PBKDF2_ITERATIONS = 600000 // OWASP 2023 recommendation for SHA-256

/**
 * Derive an encryption key from password using PBKDF2.
 * @param {string} password - User's password
 * @param {Uint8Array} salt - 16-byte salt
 * @returns {Promise<Uint8Array>} 256-bit derived key
 */
export async function deriveKey(password, salt) {
  const encoder = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  )

  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256'
    },
    keyMaterial,
    256 // 32 bytes
  )

  return new Uint8Array(bits)
}

/**
 * Hash the derived key for server verification.
 * Server stores this hash, not the key itself.
 * @param {Uint8Array} key - Derived encryption key
 * @returns {Promise<Uint8Array>} SHA-256 hash of key
 */
export async function hashKey(key) {
  const hash = await crypto.subtle.digest('SHA-256', key)
  return new Uint8Array(hash)
}

/**
 * Generate a random salt for key derivation.
 * @returns {Uint8Array} 16-byte random salt
 */
export function generateSalt() {
  return crypto.getRandomValues(new Uint8Array(16))
}

/**
 * Encrypt data using AES-256-GCM.
 * @param {Uint8Array} key - 256-bit encryption key
 * @param {Uint8Array} plaintext - Data to encrypt
 * @returns {Promise<Uint8Array>} IV (12 bytes) || ciphertext || auth tag (16 bytes)
 */
export async function encrypt(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12))

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  )

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    plaintext
  )

  // Format: IV (12 bytes) || ciphertext || auth tag (included by Web Crypto)
  const result = new Uint8Array(12 + ciphertext.byteLength)
  result.set(iv)
  result.set(new Uint8Array(ciphertext), 12)

  return result
}

/**
 * Decrypt data using AES-256-GCM.
 * @param {Uint8Array} key - 256-bit encryption key
 * @param {Uint8Array} ciphertext - IV || ciphertext || auth tag
 * @returns {Promise<Uint8Array>} Decrypted plaintext
 * @throws {Error} If decryption fails (wrong key or tampered data)
 */
export async function decrypt(key, ciphertext) {
  const iv = ciphertext.slice(0, 12)
  const data = ciphertext.slice(12)

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  )

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    data
  )

  return new Uint8Array(plaintext)
}

/**
 * Securely wipe a Uint8Array by overwriting with random data then zeros.
 * This is best-effort in JavaScript due to potential memory copies.
 * @param {Uint8Array|null} array - Array to wipe
 */
export function wipe(array) {
  if (array && array.length > 0) {
    // Overwrite with random data
    crypto.getRandomValues(array)
    // Then zero fill
    array.fill(0)
  }
}

/**
 * Convert Uint8Array to base64 string.
 * Uses chunked approach to avoid stack overflow on large files.
 * @param {Uint8Array} bytes - Bytes to encode
 * @returns {string} Base64 encoded string
 */
export function toBase64(bytes) {
  // Process in chunks to avoid "Maximum call stack size exceeded" error
  // when using spread operator on large arrays
  const CHUNK_SIZE = 0x8000 // 32KB chunks
  let binary = ''
  for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
    const chunk = bytes.subarray(i, i + CHUNK_SIZE)
    binary += String.fromCharCode.apply(null, chunk)
  }
  return btoa(binary)
}

/**
 * Convert base64 string to Uint8Array.
 * @param {string} str - Base64 encoded string
 * @returns {Uint8Array} Decoded bytes
 */
export function fromBase64(str) {
  return Uint8Array.from(atob(str), c => c.charCodeAt(0))
}

/**
 * Encrypt a string.
 * @param {Uint8Array} key - Encryption key
 * @param {string} text - Text to encrypt
 * @returns {Promise<Uint8Array>} Encrypted data
 */
export async function encryptText(key, text) {
  const encoder = new TextEncoder()
  return encrypt(key, encoder.encode(text))
}

/**
 * Decrypt to a string.
 * @param {Uint8Array} key - Encryption key
 * @param {Uint8Array} ciphertext - Encrypted data
 * @returns {Promise<string>} Decrypted text
 */
export async function decryptText(key, ciphertext) {
  const decoder = new TextDecoder()
  const plaintext = await decrypt(key, ciphertext)
  return decoder.decode(plaintext)
}
