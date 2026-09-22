#!/bin/bash
# PiAPManager.app paketini uretir ve ad-hoc imzalar.
set -euo pipefail
cd "$(dirname "$0")"
swift build -c release 2>&1 | grep -vE "^\[|Compiling|Build complete" || true
BIN=.build/release/PiAPManager
[ -x "$BIN" ] || { echo "derleme basarisiz"; exit 1; }
APP=PiAPManager.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/PiAPManager"
cp Resources/Info.plist "$APP/Contents/Info.plist"
[ -f Resources/AppIcon.icns ] && cp Resources/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"   # ./make-icon.swift regenerates it
printf 'APPL????' > "$APP/Contents/PkgInfo"
codesign --force --deep -s - "$APP" >/dev/null 2>&1
echo "OK: $(pwd)/$APP"
