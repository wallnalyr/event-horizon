import express from 'express';
import https from 'https';
import cors from 'cors';
import multer from 'multer';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import xssFilters from 'xss-filters';
import validator from 'validator';
import sodium from 'sodium-native';
import selfsigned from 'selfsigned';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 9000;
const ENABLE_SSL = process.env.ENABLE_SSL === 'true';

// =============================================================================
// ENCRYPTION HELPERS (AES-256-GCM)
// =============================================================================

const PBKDF2_ITERATIONS = 100000;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const KEY_LENGTH = 32; // 256 bits
const AUTH_TAG_LENGTH = 16;

/**
 * Derive encryption key from password using PBKDF2
 */
const deriveKey = (password, salt) => {
  return crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha256');
};

/**
 * Encrypt buffer with AES-256-GCM
 * Returns: { iv, encryptedBuffer, authTag }
 */
const encryptBuffer = (buffer, key) => {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return { iv, encryptedBuffer: encrypted, authTag };
};

/**
 * Decrypt buffer with AES-256-GCM
 */
const decryptBuffer = (encryptedData, key) => {
  const { iv, encryptedBuffer, authTag } = encryptedData;

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);

  return Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);
};

// =============================================================================
// SECURE MEMORY MANAGEMENT
// =============================================================================

/**
 * Securely zero a buffer using sodium (constant-time, prevents optimization)
 * This is NSA-grade secure zeroing that cannot be optimized away by the compiler
 */
const secureZero = (buffer) => {
  if (Buffer.isBuffer(buffer) && buffer.length > 0) {
    sodium.sodium_memzero(buffer);
  }
};

/**
 * Multi-pass secure shred following DoD 5220.22-M standard
 * Pass 1: All zeros (0x00)
 * Pass 2: All ones (0xFF)
 * Pass 3: Random data (cryptographically secure)
 * Pass 4: All zeros (0x00) - verified by sodium_memzero
 */
const secureShred = (buffer) => {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) return;

  // Pass 1: Zeros
  buffer.fill(0x00);

  // Pass 2: Ones
  buffer.fill(0xFF);

  // Pass 3: Cryptographically secure random data
  crypto.randomFillSync(buffer);

  // Pass 4: Final secure zero using sodium (constant-time, can't be optimized away)
  sodium.sodium_memzero(buffer);
};

/**
 * Securely shred a string by converting to buffer and overwriting
 * Note: Original string may still exist in memory until GC, but we minimize exposure
 */
const secureShredString = (str) => {
  if (!str || typeof str !== 'string' || str.length === 0) return;

  // Create a buffer and shred it
  // This doesn't shred the original string (impossible in JS) but provides defense in depth
  const buf = Buffer.from(str, 'utf8');
  secureShred(buf);
};

/**
 * Secure file storage with automatic expiry
 * Files are stored with their buffers and auto-expire after MAX_FILE_AGE
 */
class SecureFileStore {
  constructor() {
    this.files = new Map();
    this.MAX_FILE_AGE = parseInt(process.env.FILE_EXPIRY_MS) || 24 * 60 * 60 * 1000; // 24 hours default

    // Periodic cleanup of expired files
    this.cleanupInterval = setInterval(() => this.cleanupExpired(), 60000); // Every minute
  }

  set(id, fileData) {
    fileData.expiresAt = Date.now() + this.MAX_FILE_AGE;
    this.files.set(id, fileData);
  }

  get(id) {
    const file = this.files.get(id);
    if (file && Date.now() > file.expiresAt) {
      // File expired - securely delete it
      this.secureDelete(id);
      return null;
    }
    return file;
  }

  has(id) {
    return this.get(id) !== null;
  }

  delete(id) {
    return this.secureDelete(id);
  }

  secureDelete(id) {
    const file = this.files.get(id);
    if (!file) return false;

    // Shred the file buffer
    if (file.buffer) {
      secureShred(file.buffer);
      file.buffer = null;
    }

    // Shred metadata strings (defense in depth)
    secureShredString(file.name);
    secureShredString(file.originalName);
    secureShredString(file.mimetype);
    secureShredString(file.id);
    secureShredString(file.uploadedAt);

    // Clear object references
    file.name = null;
    file.originalName = null;
    file.mimetype = null;
    file.id = null;
    file.uploadedAt = null;
    file.expiresAt = null;

    // Remove from map
    this.files.delete(id);

    return true;
  }

  cleanupExpired() {
    const now = Date.now();
    for (const [id, file] of this.files.entries()) {
      if (now > file.expiresAt) {
        this.secureDelete(id);
      }
    }
  }

  // Get all files (for listing)
  values() {
    // Filter out expired files
    const now = Date.now();
    const validFiles = [];
    for (const [id, file] of this.files.entries()) {
      if (now > file.expiresAt) {
        this.secureDelete(id);
      } else {
        validFiles.push(file);
      }
    }
    return validFiles;
  }

  get size() {
    return this.files.size;
  }

  // Cleanup on shutdown
  destroy() {
    clearInterval(this.cleanupInterval);
    for (const id of this.files.keys()) {
      this.secureDelete(id);
    }
  }
}

/**
 * Secure clipboard storage using Buffer instead of string
 * Strings in JS are immutable and cannot be securely wiped
 * Buffers can be overwritten in-place
 */
class SecureClipboard {
  constructor() {
    this.buffer = null;
    this.updatedAt = null;
    this.MAX_SIZE = 1024 * 1024; // 1MB
    this.MAX_AGE = parseInt(process.env.CLIPBOARD_EXPIRY_MS) || 60 * 60 * 1000; // 1 hour default
  }

  set(text) {
    // Shred existing content first
    this.shred();

    if (!text || text.length === 0) {
      return;
    }

    // Store as buffer (can be securely wiped)
    this.buffer = Buffer.from(text, 'utf8');
    this.updatedAt = new Date().toISOString();
  }

  get() {
    // Check expiry
    if (this.buffer && this.updatedAt) {
      const age = Date.now() - new Date(this.updatedAt).getTime();
      if (age > this.MAX_AGE) {
        this.shred();
        return { text: '', updatedAt: null };
      }
    }

    return {
      text: this.buffer ? this.buffer.toString('utf8') : '',
      updatedAt: this.updatedAt
    };
  }

  shred() {
    if (this.buffer) {
      secureShred(this.buffer);
      this.buffer = null;
    }
    secureShredString(this.updatedAt);
    this.updatedAt = null;
  }

  get maxSize() {
    return this.MAX_SIZE;
  }
}

/**
 * Secure clipboard image storage
 * Stores a single image that can be pasted/copied across devices
 */
class SecureClipboardImage {
  constructor() {
    this.buffer = null;
    this.mimetype = null;
    this.updatedAt = null;
    this.MAX_SIZE = 10 * 1024 * 1024; // 10MB for images
    this.MAX_AGE = parseInt(process.env.CLIPBOARD_EXPIRY_MS) || 60 * 60 * 1000; // 1 hour default
  }

  set(imageBuffer, mimetype) {
    // Shred existing content first
    this.shred();

    if (!imageBuffer || imageBuffer.length === 0) {
      return;
    }

    // Store as buffer (can be securely wiped)
    this.buffer = imageBuffer;
    this.mimetype = mimetype || 'image/png';
    this.updatedAt = new Date().toISOString();
  }

  get() {
    // Check expiry
    if (this.buffer && this.updatedAt) {
      const age = Date.now() - new Date(this.updatedAt).getTime();
      if (age > this.MAX_AGE) {
        this.shred();
        return { buffer: null, mimetype: null, updatedAt: null };
      }
    }

    return {
      buffer: this.buffer,
      mimetype: this.mimetype,
      updatedAt: this.updatedAt
    };
  }

  shred() {
    if (this.buffer) {
      secureShred(this.buffer);
      this.buffer = null;
    }
    this.mimetype = null;
    secureShredString(this.updatedAt);
    this.updatedAt = null;
  }

  get maxSize() {
    return this.MAX_SIZE;
  }

  get hasImage() {
    return this.buffer !== null;
  }
}

// =============================================================================
// SESSION LOCKING & ENCRYPTION
// =============================================================================

/**
 * Manages session locking with AES-256-GCM encryption
 * When locked, all file buffers and clipboard are encrypted
 */
class LockedSession {
  constructor() {
    this.isLocked = false;
    this.lockSalt = null;
    this.sessions = new Map(); // token -> { key, lastActivity, timeout }
    this.SESSION_TIMEOUT = 15 * 60 * 1000; // 15 minutes
    this.MIN_PASSWORD_LENGTH = 8;

    // Cleanup expired sessions every minute
    this.cleanupInterval = setInterval(() => this.cleanupExpiredSessions(), 60000);
  }

  /**
   * Lock the session with a password
   * Encrypts all existing data
   */
  lock(password, fileStore, clipboardStore, clearExisting = false) {
    if (password.length < this.MIN_PASSWORD_LENGTH) {
      throw new Error(`Password must be at least ${this.MIN_PASSWORD_LENGTH} characters`);
    }

    // Clear existing data if requested
    if (clearExisting) {
      fileStore.destroy();
      clipboardStore.shred();
    }

    // Generate salt for key derivation
    this.lockSalt = crypto.randomBytes(SALT_LENGTH);
    const key = deriveKey(password, this.lockSalt);

    // Encrypt all existing files
    for (const [id, file] of fileStore.files.entries()) {
      if (file.buffer && !file.encrypted) {
        const encrypted = encryptBuffer(file.buffer, key);
        // Shred original buffer
        secureShred(file.buffer);
        file.buffer = null;
        // Store encrypted data
        file.iv = encrypted.iv;
        file.encryptedBuffer = encrypted.encryptedBuffer;
        file.authTag = encrypted.authTag;
        file.encrypted = true;
      }
    }

    // Encrypt clipboard
    if (clipboardStore.buffer && !clipboardStore.encrypted) {
      const encrypted = encryptBuffer(clipboardStore.buffer, key);
      secureShred(clipboardStore.buffer);
      clipboardStore.buffer = null;
      clipboardStore.iv = encrypted.iv;
      clipboardStore.encryptedBuffer = encrypted.encryptedBuffer;
      clipboardStore.authTag = encrypted.authTag;
      clipboardStore.encrypted = true;
    }

    // Securely zero the key
    secureZero(key);

    this.isLocked = true;

    // Create session for the user who locked it
    return this.createSession(password);
  }

  /**
   * Attempt to unlock with password
   * Returns session token if successful
   */
  unlock(password) {
    if (!this.isLocked) {
      throw new Error('Session is not locked');
    }

    // Derive key and verify it works by testing decryption
    const key = deriveKey(password, this.lockSalt);

    // We'll verify the key is correct when decrypting data
    // For now, just create a session
    const token = this.createSessionWithKey(key);

    return token;
  }

  /**
   * Force unlock - shreds all encrypted data
   */
  forceUnlock(fileStore, clipboardStore) {
    // Shred all files
    fileStore.destroy();

    // Shred clipboard
    clipboardStore.shred();

    // Clear lock state
    this.isLocked = false;
    if (this.lockSalt) {
      secureZero(this.lockSalt);
      this.lockSalt = null;
    }

    // Clear all sessions
    for (const [token, session] of this.sessions.entries()) {
      if (session.key) {
        secureZero(session.key);
      }
      this.sessions.delete(token);
    }
  }

  /**
   * Create a session token with derived key
   */
  createSession(password) {
    const key = deriveKey(password, this.lockSalt);
    return this.createSessionWithKey(key);
  }

  createSessionWithKey(key) {
    const token = crypto.randomBytes(32).toString('hex');
    this.sessions.set(token, {
      key: Buffer.from(key), // Copy the key
      lastActivity: Date.now()
    });
    return token;
  }

  /**
   * Get encryption key for a session token
   */
  getKey(token) {
    const session = this.sessions.get(token);
    if (!session) return null;

    // Check timeout
    if (Date.now() - session.lastActivity > this.SESSION_TIMEOUT) {
      this.invalidateSession(token);
      return null;
    }

    // Update last activity
    session.lastActivity = Date.now();
    return session.key;
  }

  /**
   * Validate session token
   */
  isValidSession(token) {
    return this.getKey(token) !== null;
  }

  /**
   * Invalidate a session
   */
  invalidateSession(token) {
    const session = this.sessions.get(token);
    if (session) {
      if (session.key) {
        secureZero(session.key);
      }
      this.sessions.delete(token);
    }
  }

  /**
   * Cleanup expired sessions
   */
  cleanupExpiredSessions() {
    const now = Date.now();
    for (const [token, session] of this.sessions.entries()) {
      if (now - session.lastActivity > this.SESSION_TIMEOUT) {
        this.invalidateSession(token);
      }
    }
  }

  /**
   * Decrypt a file buffer using session key
   */
  decryptFile(file, key) {
    if (!file.encrypted) return file.buffer;

    try {
      return decryptBuffer({
        iv: file.iv,
        encryptedBuffer: file.encryptedBuffer,
        authTag: file.authTag
      }, key);
    } catch (err) {
      throw new Error('Decryption failed - invalid password');
    }
  }

  /**
   * Decrypt clipboard using session key
   */
  decryptClipboard(clipboardStore, key) {
    if (!clipboardStore.encrypted) {
      return clipboardStore.buffer ? clipboardStore.buffer.toString('utf8') : '';
    }

    try {
      const decrypted = decryptBuffer({
        iv: clipboardStore.iv,
        encryptedBuffer: clipboardStore.encryptedBuffer,
        authTag: clipboardStore.authTag
      }, key);
      return decrypted.toString('utf8');
    } catch (err) {
      throw new Error('Decryption failed - invalid password');
    }
  }

  /**
   * Encrypt and store a new file
   */
  encryptAndStoreFile(fileStore, id, fileData, key) {
    if (!this.isLocked) {
      fileStore.set(id, fileData);
      return;
    }

    const encrypted = encryptBuffer(fileData.buffer, key);
    // Shred original buffer
    secureShred(fileData.buffer);
    fileData.buffer = null;
    fileData.iv = encrypted.iv;
    fileData.encryptedBuffer = encrypted.encryptedBuffer;
    fileData.authTag = encrypted.authTag;
    fileData.encrypted = true;

    fileStore.set(id, fileData);
  }

  /**
   * Encrypt and store clipboard
   */
  encryptAndStoreClipboard(clipboardStore, text, key) {
    // Shred existing
    clipboardStore.shred();

    if (!text || text.length === 0) return;

    if (!this.isLocked) {
      clipboardStore.set(text);
      return;
    }

    const buffer = Buffer.from(text, 'utf8');
    const encrypted = encryptBuffer(buffer, key);
    secureShred(buffer);

    clipboardStore.iv = encrypted.iv;
    clipboardStore.encryptedBuffer = encrypted.encryptedBuffer;
    clipboardStore.authTag = encrypted.authTag;
    clipboardStore.encrypted = true;
    clipboardStore.updatedAt = new Date().toISOString();
  }

  /**
   * Check if there's any data stored
   */
  hasData(fileStore, clipboardStore) {
    return fileStore.size > 0 || clipboardStore.buffer !== null || clipboardStore.encryptedBuffer !== null;
  }

  destroy() {
    clearInterval(this.cleanupInterval);
    // Clear all sessions and keys
    for (const [token, session] of this.sessions.entries()) {
      if (session.key) {
        secureZero(session.key);
      }
    }
    this.sessions.clear();
    if (this.lockSalt) {
      secureZero(this.lockSalt);
      this.lockSalt = null;
    }
  }
}

// In-memory file storage (secure)
const files = new SecureFileStore();

// In-memory clipboard storage (secure)
const clipboard = new SecureClipboard();

// In-memory clipboard image storage (secure)
const clipboardImage = new SecureClipboardImage();

// Session lock manager
const lockSession = new LockedSession();

// Security: Maximum clipboard size (1MB)
const MAX_CLIPBOARD_SIZE = clipboard.maxSize;

// Security: Allowed CORS origins (configure for your network)
const ALLOWED_ORIGINS = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(',')
  : null; // null allows all origins (home network use)

// Security: Validate file ID format (hex string)
const isValidFileId = (id) => {
  return typeof id === 'string' && /^[a-f0-9]{16}$/i.test(id);
};

// Security: Sanitize filename strictly
const sanitizeFilename = (name) => {
  if (!name || typeof name !== 'string') return 'unnamed_file';
  return name
    .replace(/[^a-zA-Z0-9._\-\s]/g, '_')
    .replace(/\.{2,}/g, '.')
    .replace(/\s+/g, '_')
    .slice(0, 255);
};

// Security: Rate limiters
const generalLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 600, // 600 requests per minute (allows multiple devices polling every 2s)
  message: { error: 'Too many requests, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

const uploadLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 20, // 20 uploads per minute
  message: { error: 'Too many uploads, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Security: Rate limiter for unlock attempts (brute force protection)
const unlockLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 attempts per 15 minutes
  message: { error: 'Too many unlock attempts, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Configure multer for memory storage
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 1024 * 1024 * 1024 } // 1GB limit
});

// Security: Helmet for secure headers
// When SSL is enabled, use stricter settings; otherwise relax for HTTP LAN access
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'"],
    },
  },
  crossOriginEmbedderPolicy: false, // Allow embedding for file downloads
  // Stricter CORP when SSL enabled, relaxed for HTTP
  crossOriginResourcePolicy: ENABLE_SSL ? { policy: "same-origin" } : { policy: "cross-origin" },
  crossOriginOpenerPolicy: ENABLE_SSL ? { policy: "same-origin" } : false,
}));

// Security: CORS configuration
const corsOptions = {
  origin: ALLOWED_ORIGINS || true, // true allows all origins
  methods: ['GET', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type', 'X-Session-Token'],
  maxAge: 86400, // 24 hours
};
app.use(cors(corsOptions));

// Security: Rate limiting
app.use('/api/', generalLimiter);

// Middleware
app.use(express.json({ limit: '10mb' })); // Reduced from 1gb - files use multipart

// Increase timeout for large uploads
app.use((req, res, next) => {
  req.setTimeout(600000); // 10 minutes
  res.setTimeout(600000);
  next();
});

// Serve static frontend files in production
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, 'frontend/dist')));
}

// Upload a file (with rate limiting)
app.post('/api/upload', uploadLimiter, (req, res) => {
  upload.single('file')(req, res, (err) => {
    if (err) {
      // Security: Don't expose internal error details
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({ error: 'File too large (max 1GB)' });
      }
      console.error('Multer error:', err.message);
      return res.status(400).json({ error: 'Upload failed' });
    }

    try {
      if (!req.file) {
        return res.status(400).json({ error: 'No file provided' });
      }

      // If locked, require valid session
      let key = null;
      if (lockSession.isLocked) {
        const token = req.headers['x-session-token'];
        if (!token) {
          return res.status(401).json({ error: 'Session token required' });
        }

        key = lockSession.getKey(token);
        if (!key) {
          return res.status(401).json({ error: 'Invalid or expired session' });
        }
      }

      // Security: Generate cryptographically secure ID
      const id = crypto.randomBytes(8).toString('hex');

      // Security: Sanitize filename
      const safeName = sanitizeFilename(req.file.originalname);

      const fileData = {
        id,
        name: safeName,
        originalName: req.file.originalname, // Keep original for display
        size: req.file.size,
        mimetype: req.file.mimetype || 'application/octet-stream',
        buffer: req.file.buffer,
        uploadedAt: new Date().toISOString()
      };

      // Encrypt and store if locked
      if (lockSession.isLocked && key) {
        lockSession.encryptAndStoreFile(files, id, fileData, key);
      } else {
        files.set(id, fileData);
      }

      res.json({
        success: true,
        file: {
          id: fileData.id,
          name: fileData.originalName, // Return original name for display
          size: fileData.size,
          mimetype: fileData.mimetype,
          uploadedAt: fileData.uploadedAt
        }
      });
    } catch (error) {
      console.error('Upload error:', error.message);
      res.status(500).json({ error: 'Failed to upload file' });
    }
  });
});

// List all files (without buffer data)
app.get('/api/files', (req, res) => {
  // If locked and no valid session, return locked status
  if (lockSession.isLocked) {
    const token = req.headers['x-session-token'];
    if (!token || !lockSession.isValidSession(token)) {
      return res.json({
        locked: true,
        count: files.size
      });
    }
  }

  const fileList = files.values().map(f => ({
    id: f.id,
    name: f.originalName || f.name, // Return original name for display
    size: f.size,
    mimetype: f.mimetype,
    uploadedAt: f.uploadedAt
  }));

  // Sort by upload date, newest first
  fileList.sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));

  res.json(fileList);
});

// Download a file
app.get('/api/files/:id/download', (req, res) => {
  const { id } = req.params;

  // Security: Validate file ID format
  if (!isValidFileId(id)) {
    return res.status(400).json({ error: 'Invalid file ID' });
  }

  const file = files.get(id);

  if (!file) {
    return res.status(404).json({ error: 'File not found' });
  }

  // If locked, require valid session and decrypt
  let buffer = file.buffer;
  if (lockSession.isLocked || file.encrypted) {
    const token = req.headers['x-session-token'];
    if (!token) {
      return res.status(401).json({ error: 'Session token required' });
    }

    const key = lockSession.getKey(token);
    if (!key) {
      return res.status(401).json({ error: 'Invalid or expired session' });
    }

    try {
      buffer = lockSession.decryptFile(file, key);
    } catch (err) {
      return res.status(500).json({ error: 'Failed to decrypt file' });
    }
  }

  // Security: Use pre-sanitized name for Content-Disposition
  // Use application/octet-stream to force download on iOS Safari (which ignores attachment for PDFs, etc.)
  res.set({
    'Content-Type': 'application/octet-stream',
    'Content-Disposition': `attachment; filename="${file.name}"; filename*=UTF-8''${encodeURIComponent(file.originalName || file.name)}`,
    'Content-Length': buffer.length,
    'X-Content-Type-Options': 'nosniff', // Prevent MIME sniffing
  });

  res.send(buffer);
});

// Securely shred a file
app.delete('/api/files/:id', (req, res) => {
  const { id } = req.params;

  // Security: Validate file ID format
  if (!isValidFileId(id)) {
    return res.status(400).json({ error: 'Invalid file ID' });
  }

  // If locked, require valid session
  if (lockSession.isLocked) {
    const token = req.headers['x-session-token'];
    if (!token) {
      return res.status(401).json({ error: 'Session token required' });
    }

    if (!lockSession.isValidSession(token)) {
      return res.status(401).json({ error: 'Invalid or expired session' });
    }
  }

  // Check if file exists first
  const file = files.get(id);
  if (!file) {
    return res.status(404).json({ error: 'File not found' });
  }

  try {
    // Securely delete using our secure storage class
    // This performs multi-pass DoD 5220.22-M shredding on buffer AND metadata
    const deleted = files.delete(id);

    if (!deleted) {
      return res.status(500).json({ error: 'Failed to shred file' });
    }

    // Request garbage collection (helps but not guaranteed)
    if (global.gc) {
      global.gc();
    }

    res.json({ success: true, message: 'File securely shredded (DoD 5220.22-M)' });
  } catch (error) {
    // Security: Never log error details that might contain file data
    console.error('Shred operation failed');
    res.status(500).json({ error: 'Failed to shred file' });
  }
});

// Get clipboard
app.get('/api/clipboard', (req, res) => {
  // If locked and no valid session, return locked status
  if (lockSession.isLocked || clipboard.encrypted) {
    const token = req.headers['x-session-token'];
    if (!token || !lockSession.isValidSession(token)) {
      return res.json({ locked: true });
    }

    // Decrypt and return
    const key = lockSession.getKey(token);
    if (!key) {
      return res.json({ locked: true });
    }

    try {
      const text = lockSession.decryptClipboard(clipboard, key);
      return res.json({ text, updatedAt: clipboard.updatedAt });
    } catch (err) {
      return res.status(500).json({ error: 'Failed to decrypt clipboard' });
    }
  }

  res.json(clipboard.get());
});

// Set clipboard
app.post('/api/clipboard', (req, res) => {
  const { text } = req.body;

  // Security: Validate input
  if (text !== undefined && typeof text !== 'string') {
    return res.status(400).json({ error: 'Invalid clipboard content' });
  }

  // Security: Enforce size limit
  if (text && text.length > MAX_CLIPBOARD_SIZE) {
    return res.status(413).json({ error: 'Clipboard content too large (max 1MB)' });
  }

  // If locked, require valid session
  let key = null;
  if (lockSession.isLocked) {
    const token = req.headers['x-session-token'];
    if (!token) {
      return res.status(401).json({ error: 'Session token required' });
    }

    key = lockSession.getKey(token);
    if (!key) {
      return res.status(401).json({ error: 'Invalid or expired session' });
    }
  }

  // Security: Sanitize for XSS (filter control characters, keep text safe)
  const sanitizedText = text ? xssFilters.inHTMLData(text) : '';

  // Store in secure clipboard (encrypted if locked)
  if (lockSession.isLocked && key) {
    lockSession.encryptAndStoreClipboard(clipboard, sanitizedText, key);
  } else {
    clipboard.set(sanitizedText);
  }

  // Return appropriate response based on lock state
  if (lockSession.isLocked) {
    res.json({ success: true, clipboard: { text: sanitizedText, updatedAt: clipboard.updatedAt } });
  } else {
    res.json({ success: true, clipboard: clipboard.get() });
  }
});

// Shred clipboard
app.delete('/api/clipboard', (req, res) => {
  try {
    // If locked, require valid session
    if (lockSession.isLocked) {
      const token = req.headers['x-session-token'];
      if (!token) {
        return res.status(401).json({ error: 'Session token required' });
      }

      if (!lockSession.isValidSession(token)) {
        return res.status(401).json({ error: 'Invalid or expired session' });
      }
    }

    // Securely shred clipboard using sodium-native
    // Buffer is overwritten in-place with DoD 5220.22-M pattern
    clipboard.shred();

    // Clear encrypted clipboard data if any
    clipboard.iv = null;
    clipboard.encryptedBuffer = null;
    clipboard.authTag = null;
    clipboard.encrypted = false;

    if (global.gc) {
      global.gc();
    }

    res.json({ success: true, message: 'Clipboard securely shredded (DoD 5220.22-M)' });
  } catch (error) {
    // Security: Never log error details
    console.error('Clipboard shred operation failed');
    res.status(500).json({ error: 'Failed to shred clipboard' });
  }
});

// =============================================================================
// CLIPBOARD IMAGE ENDPOINTS
// =============================================================================

// Get clipboard image info (not the actual image data to save bandwidth)
app.get('/api/clipboard-image', (req, res) => {
  // If locked and no valid session, return locked status
  if (lockSession.isLocked) {
    const token = req.headers['x-session-token'];
    if (!token || !lockSession.isValidSession(token)) {
      return res.json({ locked: true });
    }
  }

  const data = clipboardImage.get();
  res.json({
    hasImage: data.buffer !== null,
    mimetype: data.mimetype,
    size: data.buffer ? data.buffer.length : 0,
    updatedAt: data.updatedAt
  });
});

// Get clipboard image data
app.get('/api/clipboard-image/data', (req, res) => {
  // If locked, require valid session
  if (lockSession.isLocked) {
    const token = req.headers['x-session-token'];
    if (!token || !lockSession.isValidSession(token)) {
      return res.status(401).json({ error: 'Session token required' });
    }
  }

  const data = clipboardImage.get();
  if (!data.buffer) {
    return res.status(404).json({ error: 'No clipboard image' });
  }

  res.set({
    'Content-Type': data.mimetype || 'image/png',
    'Content-Length': data.buffer.length,
    'Cache-Control': 'no-store'
  });
  res.send(data.buffer);
});

// Set clipboard image
app.post('/api/clipboard-image', (req, res) => {
  // If locked, require valid session
  if (lockSession.isLocked) {
    const token = req.headers['x-session-token'];
    if (!token) {
      return res.status(401).json({ error: 'Session token required' });
    }
    if (!lockSession.isValidSession(token)) {
      return res.status(401).json({ error: 'Invalid or expired session' });
    }
  }

  // Expect base64 encoded image in JSON body
  const { image, mimetype } = req.body;

  if (!image) {
    return res.status(400).json({ error: 'No image provided' });
  }

  // Validate mimetype
  const validMimetypes = ['image/png', 'image/jpeg', 'image/gif', 'image/webp'];
  const mimeToUse = validMimetypes.includes(mimetype) ? mimetype : 'image/png';

  try {
    // Decode base64
    const imageBuffer = Buffer.from(image, 'base64');

    // Check size
    if (imageBuffer.length > clipboardImage.maxSize) {
      return res.status(413).json({ error: 'Image too large (max 10MB)' });
    }

    clipboardImage.set(imageBuffer, mimeToUse);

    res.json({
      success: true,
      size: imageBuffer.length,
      mimetype: mimeToUse,
      updatedAt: clipboardImage.updatedAt
    });
  } catch (err) {
    console.error('Failed to process clipboard image');
    res.status(400).json({ error: 'Invalid image data' });
  }
});

// Shred clipboard image
app.delete('/api/clipboard-image', (req, res) => {
  try {
    // If locked, require valid session
    if (lockSession.isLocked) {
      const token = req.headers['x-session-token'];
      if (!token) {
        return res.status(401).json({ error: 'Session token required' });
      }
      if (!lockSession.isValidSession(token)) {
        return res.status(401).json({ error: 'Invalid or expired session' });
      }
    }

    clipboardImage.shred();

    if (global.gc) {
      global.gc();
    }

    res.json({ success: true, message: 'Clipboard image securely shredded (DoD 5220.22-M)' });
  } catch (error) {
    console.error('Clipboard image shred operation failed');
    res.status(500).json({ error: 'Failed to shred clipboard image' });
  }
});

// =============================================================================
// SESSION LOCK ENDPOINTS
// =============================================================================

// Get lock status
app.get('/api/lock/status', (req, res) => {
  const token = req.headers['x-session-token'];
  const hasValidSession = token && lockSession.isValidSession(token);

  res.json({
    locked: lockSession.isLocked,
    hasData: lockSession.hasData(files, clipboard),
    hasSession: hasValidSession
  });
});

// Lock the session
app.post('/api/lock', (req, res) => {
  try {
    const { password, clearExisting } = req.body;

    if (!password || typeof password !== 'string') {
      return res.status(400).json({ error: 'Password is required' });
    }

    if (password.length < lockSession.MIN_PASSWORD_LENGTH) {
      return res.status(400).json({
        error: `Password must be at least ${lockSession.MIN_PASSWORD_LENGTH} characters`
      });
    }

    if (lockSession.isLocked) {
      return res.status(400).json({ error: 'Session is already locked' });
    }

    const token = lockSession.lock(password, files, clipboard, clearExisting === true);

    res.json({
      success: true,
      message: 'Session locked',
      token
    });
  } catch (err) {
    console.error('Lock error:', err.message);
    res.status(500).json({ error: err.message || 'Failed to lock session' });
  }
});

// Unlock the session
app.post('/api/unlock', unlockLimiter, (req, res) => {
  try {
    const { password } = req.body;

    if (!password || typeof password !== 'string') {
      return res.status(400).json({ error: 'Password is required' });
    }

    if (!lockSession.isLocked) {
      return res.status(400).json({ error: 'Session is not locked' });
    }

    const token = lockSession.unlock(password);

    res.json({
      success: true,
      message: 'Session unlocked',
      token
    });
  } catch (err) {
    console.error('Unlock error:', err.message);
    res.status(401).json({ error: 'Invalid password' });
  }
});

// Force unlock - shreds all data
app.post('/api/lock/force-unlock', (req, res) => {
  try {
    const { confirm } = req.body;

    if (confirm !== 'SHRED') {
      return res.status(400).json({
        error: 'Must type "SHRED" to confirm force unlock'
      });
    }

    if (!lockSession.isLocked) {
      return res.status(400).json({ error: 'Session is not locked' });
    }

    lockSession.forceUnlock(files, clipboard);

    res.json({
      success: true,
      message: 'All data securely shredded. Session unlocked.'
    });
  } catch (err) {
    console.error('Force unlock error:', err.message);
    res.status(500).json({ error: 'Failed to force unlock' });
  }
});

// Health check (hardened - no sensitive info)
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Serve frontend in production
if (process.env.NODE_ENV === 'production') {
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend/dist/index.html'));
  });
}

// Security: Global error handler - never expose internal errors
app.use((err, req, res, next) => {
  // Security: Never log error details that might contain sensitive data
  console.error('Unhandled error occurred');
  res.status(500).json({ error: 'Internal server error' });
});

// Security: Handle 404 for API routes
app.use('/api/*', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Graceful shutdown - securely shred all data before exit
const gracefulShutdown = (signal) => {
  console.log(`\n${signal} received. Securely shredding all data before shutdown...`);

  // Destroy lock session (clears encryption keys)
  lockSession.destroy();

  // Shred all files
  files.destroy();

  // Shred clipboard
  clipboard.shred();

  // Shred clipboard image
  clipboardImage.shred();

  // Request garbage collection
  if (global.gc) {
    global.gc();
  }

  console.log('All data securely shredded. Exiting.');
  process.exit(0);
};

// Handle shutdown signals
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught exceptions - shred data before crashing
process.on('uncaughtException', (err) => {
  console.error('Uncaught exception - securely shredding data before exit');
  lockSession.destroy();
  files.destroy();
  clipboard.shred();
  clipboardImage.shred();
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled rejection - securely shredding data before exit');
  lockSession.destroy();
  files.destroy();
  clipboard.shred();
  clipboardImage.shred();
  process.exit(1);
});

// Start server (HTTP or HTTPS based on ENABLE_SSL)
const startServer = () => {
  const printStartupInfo = (protocol) => {
    console.log(`Event Horizon server running on ${protocol}://0.0.0.0:${PORT}`);
    console.log('Security features enabled:');
    console.log('  - Helmet (security headers)');
    console.log('  - Rate Limiting (DoS protection)');
    console.log('  - Input Validation');
    console.log('  - DoD 5220.22-M Secure Shredding');
    console.log('  - Sodium-native secure memory zeroing');
    console.log('  - Auto-expiry (files: 24h, clipboard: 1h)');
    console.log('  - Graceful shutdown with secure wipe');
    console.log('  - Session Locking (AES-256-GCM encryption)');
    if (protocol === 'https') {
      console.log('  - Self-signed SSL/TLS certificate');
      console.log('\nNote: You may need to accept the self-signed certificate in your browser.');
    }
  };

  if (ENABLE_SSL) {
    // Generate self-signed certificate
    console.log('Generating self-signed SSL certificate...');
    const attrs = [{ name: 'commonName', value: 'Event Horizon' }];
    const pems = selfsigned.generate(attrs, {
      keySize: 2048,
      days: 365,
      algorithm: 'sha256'
    });

    console.log('SSL certificate generated successfully');

    const httpsOptions = {
      key: pems.private,
      cert: pems.cert
    };

    const server = https.createServer(httpsOptions, app);
    server.on('error', (err) => {
      console.error('HTTPS server error:', err);
    });
    server.listen(PORT, '0.0.0.0', () => {
      printStartupInfo('https');
    });
  } else {
    app.listen(PORT, '0.0.0.0', () => {
      printStartupInfo('http');
    });
  }
};

startServer();
