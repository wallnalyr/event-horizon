# Wormhole — macOS floating paste box

A tiny always-on-top window that mirrors the Event Horizon web app's **Wormhole**
text box. Type in it and it syncs to your server's clipboard; **Copy** puts the
text on the macOS clipboard; **Singularity** shreds it on the server. It supports
**sealed (E2EE)** sessions and **self-signed HTTPS** on your LAN.

AppKit, single file, Command Line Tools only (no Xcode).

## Build & run

```bash
cd clients/macos-wormhole
chmod +x build.sh
./build.sh
```

`build.sh` compiles `main.swift`, assembles `Wormhole.app`, **installs it to
`/Applications`** (falls back to `~/Applications` if that isn't writable), ad-hoc
signs it, and launches it. Look for the **🌀** in the menu bar. Re-run `build.sh`
to rebuild (it kills the running instance first). Override the location with
`INSTALL_DIR=~/Applications ./build.sh`.

**Start it automatically:** open the **🌀** menu and turn on **Launch at Login**.
It registers itself as a login item via `SMAppService` (macOS 13+). Because it
registers its own bundle path, keep the app in `/Applications` (that's why
`build.sh` installs there). macOS may ask you to approve it once under
System Settings ▸ General ▸ Login Items.

## First run

1. Click the **🌀** menu → **Set Server URL…** and enter your server, e.g.
   `https://file.internal` or `http://192.168.1.10:9000`.
2. If the session is **sealed**, the box prompts for the session password. It
   derives the key locally (PBKDF2 600k / SHA-256) and unlocks — the password
   never leaves your Mac and the server only ever sees ciphertext.
3. Type. Changes save to the server (debounced); text from your other devices
   appears within ~2s (it won't clobber what you're actively typing).

**🌀 menu:** Show Wormhole · Set Server URL… · Unlock (sealed session)… ·
Launch at Login · Quit (also `⌘Q`). Move the box by dragging its dark
header/margins; resize from the edges. Position and text are remembered across launches.

## How it talks to the server

- Reads `GET /api/clipboard`, writes `POST /api/clipboard`, shreds `DELETE /api/clipboard`.
- **Sealed mode:** on a locked session it fetches `/api/lock/salt`, derives the
  key, `POST /api/unlock` (gets a session token), then encrypts/decrypts with
  **AES-256-GCM** in the same `IV‖ciphertext‖tag` format as the web app — so it's
  wire-compatible and cross-device.
- **Origin header:** the server enforces same-origin on state-changing requests
  (CSRF protection, fail-closed on a missing `Origin`). The box sends an `Origin`
  matching your server URL, so it counts as same-origin. If you set a custom
  `ALLOWED_ORIGINS` on the server, include the box's origin (your server URL) in it.

## Security notes (read once)

- **Self-signed certs are trusted permissively.** The app accepts *any* TLS
  certificate the server presents (there's no pinning). That's fine on a trusted
  LAN; don't point it at hosts you don't control.
- **The E2EE password is kept in memory only** — you re-enter it after relaunch
  (matches the web app's model). Not stored on disk. (Keychain persistence is an
  easy future add if you want it.)
- **Cached text** (the last text shown) *is* written to `UserDefaults` so the box
  isn't empty on launch. In sealed mode that means the last plaintext you saw
  lives in the app's prefs plist locally. Delete it by shredding (Singularity) or
  clear `~/Library/Preferences/com.wallnalyr.wormhole.plist`.
- E2EE requires the server to be reachable over **HTTPS or `localhost`** (a secure
  context) *for the web app*; the native box does its own crypto, so it also works
  against `http://` — but then traffic is unencrypted in transit, so prefer HTTPS.

## Troubleshooting

- **`⌘V` / `⌘C` don't work:** they route through the programmatically-built Edit
  menu; if a rebuild misbehaves, quit (🌀 → Quit) and re-run `build.sh`.
- **Lost the window:** 🌀 → Show Wormhole.
- **"Offline — can't reach …":** wrong URL, server down, or (for HTTPS) a cert the
  app couldn't complete a handshake with. Try the `http://ip:port` form to isolate.
- **Compile/link errors:** paste them back — this was written against Swift 6.3 /
  macOS 26 but built on a Linux box, so a stray fix may be needed. If an `import`
  fails with "failed to build module … textual interface may be broken," that's a
  toolchain issue, not the code.
