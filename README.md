# Event Horizon

File sharing and clipboard sync across the event horizon.

A secure, ephemeral file sharing and clipboard sync app for your local network. Upload files from one device and download them on another. All data orbits in the accretion disk (memory) and can be sent to the singularity when no longer needed.

## Features

- **Drag & Drop Upload** - Drop files directly onto the upload zone to accrete them
- **Multiple File Support** - Upload multiple files at once
- **Wormhole** - Sync text between devices with a line-numbered editor
- **Photon Capture** - Share images across devices via clipboard
- **Session Sealing** - Password-protect your session with AES-256-GCM encryption
- **Singularity Disposal** - Files are securely overwritten using DoD 5220.22-M standard:
  - Pass 1: Overwrite with zeros (0x00)
  - Pass 2: Overwrite with ones (0xFF)
  - Pass 3: Overwrite with random data
  - Pass 4: Final zero pass
- **Accretion Disk Storage** - No files are written to disk, everything stays in RAM
- **PWA Support** - Install as an app on mobile devices
- **Auto-Expiry** - Files and clipboard automatically expire after configurable time
- **Graceful Collapse** - All data is securely sent to the singularity on server shutdown
- **Self-Signed SSL** - Auto-generates HTTPS certificate on startup for secure LAN access

## Quick Start

### Docker (Recommended)

```bash
# Clone the repo
git clone https://github.com/wallnalyr/event-horizon.git
cd event-horizon

# Build and run
docker compose up -d --build

# Access at https://localhost:9000
# (Accept the self-signed certificate warning in your browser)
```

To stop: `docker compose down`

### Development

**Backend:**
```bash
cd backend
npm install
npm run dev
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

The frontend dev server runs on port 5173 and proxies API requests to the backend on port 9000.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NODE_ENV` | `development` | Set to `production` for production builds |
| `PORT` | `9000` | Server port |
| `ENABLE_SSL` | `false` | Enable self-signed HTTPS (`true` in docker-compose) |
| `FILE_EXPIRY_MS` | `86400000` | File expiry time in ms (default: 24 hours) |
| `CLIPBOARD_EXPIRY_MS` | `3600000` | Clipboard expiry time in ms (default: 1 hour) |
| `CORS_ORIGINS` | `*` | Comma-separated list of allowed origins |
| `MAX_FILE_SIZE` | `104857600` | Maximum file size in bytes (default: 100MB) |

## API Endpoints

### Files

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/upload` | Upload a file (multipart/form-data) |
| `GET` | `/api/files` | List all files in the accretion disk |
| `GET` | `/api/files/:id/download` | Download a file |
| `DELETE` | `/api/files/:id` | Send a file to the singularity |

### Wormhole (Clipboard)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/clipboard` | Get wormhole contents |
| `POST` | `/api/clipboard` | Update wormhole contents |
| `DELETE` | `/api/clipboard` | Send wormhole contents to the singularity |

### Session Sealing

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/lock/status` | Get seal status |
| `POST` | `/api/lock` | Seal session with password |
| `POST` | `/api/unlock` | Unseal session |
| `POST` | `/api/lock/force-unlock` | Emergency breach (sends all data to singularity) |

### Health

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check |

## Security Features

- **Accretion Disk Storage** - No data persists to disk
- **DoD 5220.22-M Disposal** - Secure 4-pass overwrite before deletion
- **AES-256-GCM Encryption** - Session sealing uses authenticated encryption
- **PBKDF2 Key Derivation** - 100,000 iterations for password-based keys
- **Graceful Collapse** - All data sent to singularity on SIGTERM/SIGINT
- **Rate Limiting** - Protection against brute force attacks
- **Security Headers** - Helmet.js for HTTP security headers
- **Container Hardening** - Dropped capabilities, no-new-privileges

## Security Notes

- Files are stored in the accretion disk (memory) only - they do not persist to disk
- All data is lost when the server restarts (by design)
- Session sealing encrypts data but the encryption key is held in server memory
- Intended for use on trusted local networks
- For sensitive data, always seal the session before adding content

## Tech Stack

- **Backend**: Node.js, Express, Multer, sodium-native
- **Frontend**: React, Vite, Tailwind CSS, Framer Motion
- **Design**: Space/black hole inspired design system

## License

MIT
