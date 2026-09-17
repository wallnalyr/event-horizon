#!/bin/bash
# Build, bundle, install to /Applications, sign, and launch the Wormhole box.
# Command Line Tools only — no Xcode. Run from this directory: ./build.sh
#
# Installing to a fixed location matters for "Launch at Login": the app
# registers its own bundle path with SMAppService, so it must live somewhere
# stable (not this build folder). Override with:  INSTALL_DIR=~/Applications ./build.sh
set -euo pipefail

APP="Wormhole"
INSTALL_DIR="${INSTALL_DIR:-/Applications}"

# A running binary can't be overwritten — kill it first.
pkill -x "$APP" 2>/dev/null || true

# Compile (single file; no -target/-sdk — the defaults match the OS).
swiftc main.swift -o "$APP"

# Assemble the .app bundle in a temp staging dir.
STAGE="$(mktemp -d)"
mkdir -p "$STAGE/$APP.app/Contents/MacOS"
cp Info.plist "$STAGE/$APP.app/Contents/Info.plist"
mv -f "$APP" "$STAGE/$APP.app/Contents/MacOS/$APP"
plutil -lint "$STAGE/$APP.app/Contents/Info.plist"

# Install to a stable location (fall back to ~/Applications if /Applications
# isn't writable, e.g. a non-admin account).
install_to() {
  mkdir -p "$1" && rm -rf "$1/$APP.app" && cp -R "$STAGE/$APP.app" "$1/"
}
if ! install_to "$INSTALL_DIR" 2>/dev/null; then
  echo "Couldn't write to $INSTALL_DIR — installing to ~/Applications instead."
  INSTALL_DIR="$HOME/Applications"
  install_to "$INSTALL_DIR"
fi
rm -rf "$STAGE"

# Sign in place so permissions/login-item registration persist across rebuilds.
codesign -s - --force --deep "$INSTALL_DIR/$APP.app"

open "$INSTALL_DIR/$APP.app"
echo "Installed and launched $INSTALL_DIR/$APP.app — look for the 🌀 in the menu bar."
echo "Turn on 🌀 ▸ Launch at Login to start it automatically."
