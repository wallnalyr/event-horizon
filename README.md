# Event Horizon

Ephemeral file sharing and clipboard sync for your **home network**.

Upload a file or copy some text on one device and grab it on another. Nothing is
written to disk — data lives in memory only and auto-expires, or you can send it
to the singularity (delete it) yourself. Optionally, seal a session with a
password for real end-to-end encryption.

## ⚠️ Security & Scope — Read This First

Event Horizon is a **convenience tool for a trusted local network**, hardened to
be reasonable — not a high-security vault.

- **It is NOT 100% secure.** It reduces casual exposure; it does not defend
  against a determined attacker who controls the server, the host, or your LAN.
- **Do NOT expose it to the public internet.** There are no user accounts — a
  single shared session is visible to anyone who can reach the port. Keep it
  behind your router/firewall and bind it to your LAN only.
- **For actual confidentiality, use Session Sealing (E2EE) over HTTPS.** Without
  sealing, the server can read your data. Browser crypto (and the Copy button)
  require a secure context, so E2EE only works over `https://` or `localhost` —
  put the app behind a TLS reverse proxy for LAN use.
- **Everything is ephemeral.** A restart, crash, or expiry loses your data by
  design. There is no backup.

See [Limitations & Drawbacks](#limitations--drawbacks) and
[Threat Model](#threat-model) for the honest details of what is and isn't protected.

## Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
- [Security Architecture](#security-architecture)
- [Threat Model](#threat-model)
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
- **Session Sealing** - End-to-end encrypt your session with AES-256-GCM (requires a secure context: HTTPS or `localhost`)
- **Singularity Disposal** - At-rest buffers are multi-pass overwritten (zeros / ones / random / wipe) before release
- **Accretion Disk Storage** - Nothing is persisted to disk; data lives in process memory only, obfuscated with a rotating XOR pad
- **Add to Home Screen** - Installable via a web manifest (no offline service worker)
- **Auto-Expiry** - Files (24h) and clipboard (1h) automatically expire
- **Graceful Collapse** - All data is securely shredded on server shutdown

---

## How It Works

### Data Flow Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CLIENT (Browser)                            │
│  • Optional E2EE (sealed): PBKDF2 → AES-256-GCM, client-side        │
│  • Password never leaves the browser                                │
│  • Key held in memory for the session (JS cannot guarantee a wipe)  │
└─────────────────────────────────────────────────────────────────────┘
                                   │
              HTTP by default (use an HTTPS reverse proxy for LAN)
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      SECURITY MIDDLEWARE                            │
│  • Rate limiting (600 req/min general, 20 req/min uploads)          │
│  • Same-origin validation (CSRF protection)                         │
│  • Request-body size limits                                         │
│  • Security headers (CSP, X-Frame-Options, ...)                     │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       IN-MEMORY STORAGE                             │
│  • Nothing written to disk; auto-expiry + multi-pass overwrite      │
│  • Unsealed: plaintext in RAM, XOR-obfuscated (casual-dump defense) │
│  • Sealed: only ciphertext + keyHash + salt are ever stored         │
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
| File contents | Server-readable, memory-protected | E2EE ciphertext only |
| File metadata (name, type, size) | Server-readable | **Encrypted** — the server stores an opaque metadata blob and only sees ciphertext lengths |
| Clipboard Text | Server-readable, memory-protected | E2EE ciphertext only |
| Clipboard Images | Server-readable, memory-protected | E2EE ciphertext only (image MIME type is stored in the clear) |
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

- **The server speaks plain HTTP by default.** For encryption in transit (and to
  enable E2EE / the Copy button, which need a secure context) run it behind an
  HTTPS reverse proxy or access it via `localhost`. The `Strict-Transport-Security`
  header is sent but has no effect over HTTP.
- Security headers (CSP, `X-Frame-Options: DENY`, `nosniff`, ...) prevent common web attacks
- Same-origin validation on state-changing requests for CSRF protection

### Layer 3: Server Memory Protection (FortifiedBuffer)

> **Reality check:** this layer is *obfuscation against casual inspection of a
> memory dump*, not encryption at rest. The pad sits next to the data in the same
> process heap, so anyone who can run a debugger, read `/proc/<pid>/mem`, or walk a
> coherent dump can recover the plaintext. For real confidentiality, use Sealed
> Mode (Layer 1).

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
| Scatter Storage | Data split into 4–64 chunks, stored in shuffled order. Chunk size grows with payload size so the chunk count (and its per-chunk goroutine/timer overhead) stays bounded. |
| XOR Obfuscation | Each chunk XOR'd with a cryptographic random pad |
| Pad Rotation | XOR pad regenerated every 100ms for small payloads; the interval scales up for large payloads to bound CPU/entropy cost |
| Tripwire | Best-effort Linux check for a debugger/`ptrace` tracer; on detection it shreds data and exits. Not a defense against a determined operator with host access. |
| memguard | Used for the process master key, decoy pool, and constant-time wipe. **Note:** file/clipboard payloads live in ordinary (GC) heap, *not* memguard guard pages — the XOR obfuscation is protection against casual memory inspection (`strings`/grep of a dump), not against a debugger, root `/proc/pid/mem`, or a coherent heap walk. |

### Layer 4: Secure Deletion (multi-pass overwrite)

When an at-rest buffer is deleted, expired, or the server shuts down, its backing
array is overwritten in place before release:

```
Pass 1: Overwrite with 0x00 (zeros)
Pass 2: Overwrite with 0xFF (ones)
Pass 3: Overwrite with crypto/rand random bytes
Pass 4: memguard.WipeBytes (constant-time zero)
```

**Scope & honesty:** the multi-pass pattern is inspired by the (now-retired) DoD
5220.22-M *disk* standard; for volatile RAM a single overwrite is equivalent, so
treat the extra passes as belt-and-suspenders, not a magic guarantee. Overwrites
reach the buffers held by the store, but **transient plaintext copies created by
the HTTP layer** (multipart parse buffers, the download response copy, and the
immutable Go strings produced when clipboard JSON is (de)serialized) are *not*
wiped and persist in the heap until the allocator reuses the memory.

### Layer 5: Auto-Expiry

| Data Type | Expiry Time | On Expiry |
|-----------|-------------|-----------|
| Clipboard (text & images) | 1 hour | Secure 4-pass shred |
| Files | 24 hours | Secure 4-pass shred |

### Layer 6: Rate Limiting

Per-client, keyed on the peer address (`RemoteAddr`). Proxy headers
(`X-Forwarded-For`) are ignored unless `TRUST_PROXY=true`, so a direct client
cannot forge them; the visitor table is bounded to prevent memory growth.

| Endpoint Type | Limit | Burst |
|---------------|-------|-------|
| General API | 600 req/min (10/sec) | 60 |
| Upload | 20 req/min | 5 |
| Auth (unlock / lock / force-unlock) | 10 req/min | 5 |

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
| **Secure Context Required** | The Web Crypto API (`crypto.subtle`) and clipboard write are only available in a secure context. Session Sealing (E2EE) and the one-click Copy button therefore require HTTPS or access via `localhost`; over plain `http://<LAN-IP>` they will not function. Put the app behind a TLS reverse proxy for LAN use. |
| **Shared Session, No Accounts** | A server instance is a single shared session with no per-user auth. Any device that can reach the port can read/replace unsealed data, and `force-unlock` intentionally wipes all data without a password. Cross-*site* attacks are blocked by same-origin validation, but the LAN itself is the trust boundary. |

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

**Enabling E2EE (recommended):** Session Sealing needs a secure context. On the
same machine, `http://localhost:9000` already qualifies. To seal from other
devices over the LAN, serve HTTPS — set `TLS_ENABLED=true` (a self-signed cert is
generated automatically; your browser will warn once, then E2EE works), or put
the app behind a TLS reverse proxy:

```bash
docker compose run -e TLS_ENABLED=true -p 9000:9000 fileez
# then open https://<lan-ip>:9000 and accept the self-signed certificate
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
| `MAX_MEMORY` | `536870912` | Max tracked memory in bytes (512MB). Plaintext files are accounted at ~2x their size (rotating XOR pad), so this bounds real footprint, not logical bytes. |
| `FILE_EXPIRY` | `24h` | File expiry duration |
| `CLIPBOARD_EXPIRY` | `1h` | Clipboard expiry duration |
| `RATE_LIMIT` | `600` | Requests per minute (general) |
| `UPLOAD_RATE_LIMIT` | `20` | Requests per minute (uploads) |
| `ENABLE_CORS` | `true` | Enable CORS headers |
| `ALLOWED_ORIGINS` | `*` | Comma-separated allowed origins. `*` = home-network mode: same-origin is enforced for state-changing requests (cross-site blocked), reads are permitted without credentials. |
| `TRUST_PROXY` | `false` | Honor `X-Forwarded-For`/`X-Real-IP` for the rate-limit client key. Leave off unless behind a trusted reverse proxy. |
| `TLS_ENABLED` | `false` | Serve over HTTPS. Provides the secure context E2EE and the Copy button require. |
| `TLS_CERT_FILE` | _(none)_ | PEM certificate file. If `TLS_ENABLED` and no cert/key are given, a self-signed cert is generated on startup (browser will warn; accept it to enable E2EE). |
| `TLS_KEY_FILE` | _(none)_ | PEM private-key file (pairs with `TLS_CERT_FILE`). |
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
| `GET` | `/api/health` | Health check (`{"status":"ok"}`; append `?stats=true` for memory/session stats) |
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

## Threat Model

Be realistic about what this buys you. Event Horizon assumes a **trusted LAN** and
a **non-malicious server operator**; it is a convenience tool, not a vault.

**Reasonably mitigated (on a trusted LAN):**

- Cross-site requests from other websites — same-origin validation on state-changing endpoints
- Clickjacking / MIME sniffing / basic web attacks — CSP and security headers
- Request floods and password-guessing bursts — per-IP rate limiting (stricter on auth endpoints), body-size limits
- Casual recovery of deleted data — multi-pass overwrite of at-rest buffers before release
- `strings`/grep of a raw memory dump — unsealed data is XOR-obfuscated in RAM
- Password verification timing — constant-time keyHash comparison

**Sealed mode (E2EE) additionally protects against:**

- An honest-but-curious or **later-compromised** server reading your data at rest — it only ever holds ciphertext, a salt, and a hash of your key. Requires HTTPS/secure context and a strong password.

**NOT protected against (do not rely on it for these):**

- **A server or host that is malicious right now.** It serves the app's JavaScript, so it could serve backdoored crypto and capture your password. E2EE here defends the data at rest, not against an actively hostile operator.
- **Anyone with access to your LAN / the port.** No accounts; a single shared session. This is why you must not expose it to the internet.
- **Physical access, root, a debugger, or a coherent memory/swap dump** of the host — unsealed data (and transient plaintext copies even in sealed mode) live in ordinary process memory. The XOR obfuscation and tripwire slow down casual inspection; they do not stop a determined attacker with host access.
- **Weak passwords, compromised browsers/extensions, network eavesdropping over plain HTTP.** Use a strong password and HTTPS.

If any of the "not protected" items are in your threat model, this app is not the
right tool — see [What This Is NOT Suitable For](#what-this-is-not-suitable-for).

---

## License

MIT
