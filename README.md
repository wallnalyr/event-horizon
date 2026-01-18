# Event Horizon

File sharing and clipboard sync across the event horizon.

A secure, ephemeral file sharing and clipboard sync app for your local network. Upload files from one device and download them on another. All data orbits in the accretion disk (memory) and can be sent to the singularity when no longer needed.

## Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
- [Security Architecture](#security-architecture)
- [Limitations & Drawbacks](#limitations--drawbacks)
- [Quick Start](#quick-start)
- [Environment Variables](#environment-variables)
- [API Endpoints](#api-endpoints)
- [Tech Stack](#tech-stack)

---

## Features

- **Drag & Drop Upload** - Drop files directly onto the upload zone
- **Multiple File Support** - Upload multiple files at once
- **Wormhole** - Sync text between devices with a line-numbered editor
- **Photon Capture** - Share images across devices via clipboard
- **Session Sealing** - End-to-end encrypt your session with AES-256-GCM
- **Singularity Disposal** - Files are securely overwritten using DoD 5220.22-M standard
- **Accretion Disk Storage** - No files are written to disk, everything stays in secure memory
- **PWA Support** - Install as an app on mobile devices
- **Auto-Expiry** - Files (24h) and clipboard (1h) automatically expire
- **Graceful Collapse** - All data is securely shredded on server shutdown

---

## How It Works

### Data Flow Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CLIENT (Browser)                            │
│  • Optional E2EE: PBKDF2 key derivation → AES-256-GCM encryption    │
│  • Password never leaves browser                                    │
│  • Encryption key derived client-side, wiped after use              │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                         HTTPS (encrypted in transit)
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      SECURITY MIDDLEWARE                            │
│  • Rate limiting (600 req/min general, 20 req/min uploads)          │
│  • Origin validation (CSRF protection)                              │
│  • Security headers (CSP, HSTS, X-Frame-Options)                    │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    SECURE MEMORY STORAGE                            │
│  • FortifiedBuffer with scatter + XOR obfuscation + tripwire        │
│  • Data split into 4+ chunks, stored in random order                │
│  • XOR pad rotates every 100ms with crypto random                   │
│  • Tripwire monitors for debuggers every 50ms                       │
│  • Auto-expiry with secure shredding                                │
└─────────────────────────────────────────────────────────────────────┘
```

### Unsealed Mode (Default)

When you first use Event Horizon without sealing:

1. **Upload/Paste** → Data sent to server over HTTPS
2. **Server Storage** → Data stored in `FortifiedBuffer` (memory only)
3. **Memory Protection** → Data is scattered, XOR-obfuscated, and monitored
4. **Retrieval** → Data reassembled and returned on request
5. **Deletion** → 4-pass DoD 5220.22-M secure shredding

**Note:** In unsealed mode, data is protected in memory but the server can read it.

### Sealed Mode (End-to-End Encrypted)

When you seal the session with a password:

1. **Password Entry** → Client generates 16-byte random salt
2. **Key Derivation** → PBKDF2(password, salt, 600,000 iterations, SHA-256) → 32-byte key
3. **Key Hash** → SHA-256(derived key) → sent to server for verification only
4. **Encryption** → AES-256-GCM encrypts all data client-side
5. **Server Storage** → Server stores only: keyHash, salt, encrypted blobs
6. **Unlock** → Client re-derives key from password + salt, server verifies keyHash
7. **Decryption** → Client decrypts locally; server never sees plaintext

**The server cannot decrypt sealed data** - it only stores ciphertext and verifies passwords.

### What Gets Protected

| Data Type | Unsealed | Sealed |
|-----------|----------|--------|
| Files | Server-readable, memory-protected | E2EE ciphertext only |
| Clipboard Text | Server-readable, memory-protected | E2EE ciphertext only |
| Clipboard Images | Server-readable, memory-protected | E2EE ciphertext only |
| Password | N/A | Never sent to server |
| Encryption Key | N/A | Never sent to server |
| Key Hash | N/A | Server stores (cannot reverse) |

---

## Security Architecture

### Layer 1: Client-Side Encryption (E2EE when sealed)

| Component | Implementation |
|-----------|----------------|
| Key Derivation | PBKDF2, 600,000 iterations, SHA-256 |
| Encryption | AES-256-GCM (authenticated encryption) |
| Salt | 16 bytes (128 bits), cryptographically random |
| IV/Nonce | 12 bytes (96 bits), unique per encryption |
| Auth Tag | 16 bytes (128 bits), prevents tampering |
| Ciphertext Format | `IV (12 bytes) ∥ ciphertext ∥ authTag (16 bytes)` |

### Layer 2: Transport Security

- HTTPS encryption in transit
- Security headers prevent common web attacks
- CORS and Origin validation for CSRF protection

### Layer 3: Server Memory Protection (FortifiedBuffer)

```
Original Data: [████████████████████████████████]
                            │
                    ┌───────┴───────┐
                    │  SCATTER      │
                    └───────┬───────┘
                            ▼
Chunks:         [C3] [C1] [C4] [C2]  ← Random order in memory
                            │
                    ┌───────┴───────┐
                    │  XOR PAD      │
                    └───────┬───────┘
                            ▼
Obfuscated:     [██] [██] [██] [██]  ← XOR'd with random pad
                            │
                    ┌───────┴───────┐
                    │  ROTATE       │  ← Every 100ms
                    └───────┬───────┘
                            ▼
                New pad, re-XOR all chunks
```

| Protection | Description |
|------------|-------------|
| Scatter Storage | Data split into 4+ chunks (256 bytes each), stored in shuffled order |
| XOR Obfuscation | Each chunk XOR'd with cryptographic random pad |
| Pad Rotation | XOR pad regenerated every 100ms |
| Tripwire | Monitors for debugger attachment every 50ms; triggers data destruction |
| memguard | Underlying secure memory allocation with guard pages |

### Layer 4: Secure Deletion (DoD 5220.22-M)

When data is deleted, expired, or the server shuts down:

```
Pass 1: Overwrite with 0x00 (zeros)
Pass 2: Overwrite with 0xFF (ones)
Pass 3: Overwrite with crypto/rand random bytes
Pass 4: memguard.WipeBytes (constant-time zero)
```

### Layer 5: Auto-Expiry

| Data Type | Expiry Time | On Expiry |
|-----------|-------------|-----------|
| Clipboard (text & images) | 1 hour | Secure 4-pass shred |
| Files | 24 hours | Secure 4-pass shred |

### Layer 6: Rate Limiting

| Endpoint Type | Limit | Burst |
|---------------|-------|-------|
| General API | 600 req/min (10/sec) | 60 |
| Upload | 20 req/min | 5 |

### Layer 7: Security Headers

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; script-src 'self'; ...
```

---

## Limitations & Drawbacks

### Fundamental Limitations

| Limitation | Explanation |
|------------|-------------|
| **Ephemeral by Design** | All data is lost on server restart. This is intentional but means no persistence. |
| **Memory Bound** | Limited by available RAM (default 512MB). Large files consume significant memory. |
| **Single Server** | No clustering or replication. Server failure = data loss. |
| **LAN-Focused** | Designed for trusted local networks, not public internet exposure. |

### Security Caveats

| Caveat | Details |
|--------|---------|
| **Unsealed Mode Exposure** | Without sealing, server can read all data. Only memory protections apply. |
| **RAM Forensics Still Possible** | XOR obfuscation and scattering slow down forensics but don't prevent a determined attacker with physical access and specialized tools. |
| **Client-Side JS Crypto** | Browser crypto can be compromised by XSS, malicious extensions, or compromised CDNs (mitigated by strict CSP). |
| **No Key Rotation** | Sealed sessions use a single derived key. No automatic key rotation. |
| **Password Strength Dependent** | E2EE security depends entirely on password strength. Weak passwords = weak encryption. |
| **No Forward Secrecy** | If password is compromised, all data encrypted with it is compromised. |
| **Timing Side Channels** | While keyHash comparison is constant-time, other operations may leak timing info. |

### Operational Drawbacks

| Drawback | Impact |
|----------|--------|
| **No Backup/Recovery** | Data cannot be backed up. Server crash = permanent data loss. |
| **No User Management** | Single shared session per server instance. No multi-user isolation. |
| **No Audit Logging** | No persistent logs of who accessed what (by design, for privacy). |
| **Memory Pressure** | High memory usage can trigger OOM killer on constrained systems. |
| **Browser Dependency** | Requires modern browser with Web Crypto API support. |

### What This Is NOT Suitable For

- Long-term file storage
- Mission-critical data without backups
- Multi-user environments requiring isolation
- Environments where server compromise is likely
- Regulatory compliance requiring audit trails
- Data that must survive server restarts

### What This IS Suitable For

- Quick file transfers between personal devices on a home network
- Sharing sensitive data that should auto-delete
- Clipboard sync across devices
- Temporary secure storage where ephemerality is a feature
- Environments where you control the server and network

---

## Quick Start

### Docker - Standalone

```bash
# Clone the repo
git clone https://github.com/wallnalyr/event-horizon.git
cd event-horizon

# Edit docker-compose.yml to uncomment the ports section:
#   ports:
#     - "9000:9000"

# Start the container
docker compose up -d --build

# Access at http://localhost:9000
```

### Development

**Backend (Go):**
```bash
go mod download
go run ./cmd/server
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

The frontend dev server runs on port 3000 and proxies API requests to the backend on port 9000.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `9000` | Server port |
| `HOST` | `0.0.0.0` | Server host |
| `MAX_FILE_SIZE` | `104857600` | Maximum file size in bytes (100MB) |
| `MAX_MEMORY` | `536870912` | Maximum secure memory in bytes (512MB) |
| `FILE_EXPIRY` | `24h` | File expiry duration |
| `CLIPBOARD_EXPIRY` | `1h` | Clipboard expiry duration |
| `RATE_LIMIT` | `600` | Requests per minute (general) |
| `UPLOAD_RATE_LIMIT` | `20` | Requests per minute (uploads) |
| `ENABLE_CORS` | `true` | Enable CORS headers |
| `ALLOWED_ORIGINS` | `*` | Allowed origins for CORS |
| `ENABLE_CLIPBOARD` | `true` | Enable clipboard feature |
| `ENABLE_CLIPBOARD_IMAGE` | `true` | Enable image clipboard feature |
| `ENABLE_FILE_SHARING` | `true` | Enable file sharing feature |

---

## API Endpoints

### Files

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/upload` | Upload a file (multipart/form-data) |
| `POST` | `/api/upload/encrypted` | Upload E2EE encrypted file |
| `GET` | `/api/files` | List all files |
| `GET` | `/api/files/:id` | Get file metadata |
| `GET` | `/api/files/:id/download` | Download file |
| `DELETE` | `/api/files/:id` | Securely shred file |

### Clipboard

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/clipboard` | Get clipboard text |
| `POST` | `/api/clipboard` | Set clipboard text |
| `DELETE` | `/api/clipboard` | Shred clipboard text |
| `GET` | `/api/clipboard-image` | Get image info |
| `GET` | `/api/clipboard-image/data` | Get image data |
| `POST` | `/api/clipboard-image` | Set image |
| `DELETE` | `/api/clipboard-image` | Shred image |

### Session Sealing (E2EE)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/lock/status` | Get seal status |
| `GET` | `/api/lock/salt` | Get PBKDF2 salt for key derivation |
| `POST` | `/api/lock` | Seal session (client sends keyHash, salt, encrypted blobs) |
| `POST` | `/api/unlock` | Verify keyHash, get encrypted blobs for client decryption |
| `POST` | `/api/lock/force-unlock` | Emergency: shred all data, no password needed |

### Health

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check with memory stats |
| `GET` | `/api/ping` | Simple ping |

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | Go 1.22+, chi router |
| Secure Memory | memguard, custom FortifiedBuffer |
| Cryptography | AES-256-GCM, PBKDF2, crypto/rand |
| Frontend | React 18, Vite, Tailwind CSS |
| Animations | Framer Motion |
| Design | Space/black hole theme |

---

## Security Summary

```
┌────────────────────────────────────────────────────────────────────────────┐
│                          THREAT MODEL SUMMARY                               │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  PROTECTED AGAINST:                     │  NOT PROTECTED AGAINST:          │
│  ✓ Network eavesdropping (HTTPS)        │  ✗ Physical server access        │
│  ✓ CSRF attacks (Origin validation)    │  ✗ Compromised browser/extensions│
│  ✓ XSS (strict CSP)                     │  ✗ Weak passwords (user issue)   │
│  ✓ Clickjacking (X-Frame-Options)       │  ✗ Server memory dump (advanced) │
│  ✓ Brute force (rate limiting)          │  ✗ Nation-state level forensics  │
│  ✓ Casual data recovery (4-pass shred)  │  ✗ Quantum computing (future)    │
│  ✓ Basic memory forensics (obfuscation) │  ✗ Insider server access         │
│  ✓ Debugger attachment (tripwire)       │                                  │
│  ✓ Timing attacks on password verify    │                                  │
│                                                                            │
│  SEALED MODE ADDS:                                                         │
│  ✓ Server cannot read your data                                            │
│  ✓ Compromise requires password + ciphertext                               │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## License

MIT
