#!/bin/bash
# Build, bundle, sign, and launch the Wormhole floating paste box.
# Command Line Tools only — no Xcode. Run from this directory: ./build.sh
set -euo pipefail

APP="Wormhole"

# A running binary can't be overwritten — kill it first.
pkill -x "$APP" 2>/dev/null || true

# Compile (single file; no -target/-sdk — the defaults match the OS).
swiftc main.swift -o "$APP"

# Assemble the .app bundle.
mkdir -p "$APP.app/Contents/MacOS"
cp Info.plist "$APP.app/Contents/Info.plist"
mv -f "$APP" "$APP.app/Contents/MacOS/$APP"

# Validate the plist and sign so permissions/state persist across rebuilds.
plutil -lint "$APP.app/Contents/Info.plist"
codesign -s - --force --deep "$APP.app"

open "$APP.app"
echo "Launched $APP.app — look for the 🌀 in the menu bar."
