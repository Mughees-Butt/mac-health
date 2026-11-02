#!/bin/zsh
# Builds Mac Health.app from the source files in this folder.
# It signs with your private "Mac Health Local Signing" key, so Full Disk Access survives rebuilds.
# macOS asks you to approve each signing: choose Allow, not Always Allow, so nothing can sign silently.
# The existing app is only replaced once the new one is built, signed and verified.
set -euo pipefail
cd "${0:A:h}"

APP="Mac Health.app"
IDENTITY="$(/usr/bin/security find-certificate -c "Mac Health Local Signing" -Z 2>/dev/null | awk '/SHA-1/{print $3}' || true)"
if [ -z "$IDENTITY" ]; then
  echo "The Mac Health Local Signing key is missing. Create it with ./scripts/setup-signing.sh" >&2
  exit 1
fi

WORK="$(mktemp -d)"
trap 'chmod -R u+w "$WORK"; rm -rf "$WORK"' EXIT

{
  echo 'let expectedHashes: [String: String] = ['
  for f in src/backend/server.py src/backend/scanners.py src/ui/index.html; do
    echo "  \"${f:t}\": \"$(/usr/bin/shasum -a 256 "$f" | cut -d' ' -f1)\","
  done
  echo ']'
} > "$WORK/hashes.swift"

/usr/bin/swiftc -O -target "$(uname -m)-apple-macos13" -o "$WORK/MacHealth" src/app/main.swift "$WORK/hashes.swift" -framework Cocoa -framework WebKit

NEW="$WORK/$APP"
mkdir -p "$NEW/Contents/MacOS" "$NEW/Contents/Resources"
cp "$WORK/MacHealth" "$NEW/Contents/MacOS/MacHealth"
cp src/backend/server.py src/backend/scanners.py src/ui/index.html "$NEW/Contents/Resources/"
cp src/app/Info.plist "$NEW/Contents/Info.plist"
chmod -R a-w,go-rwx "$NEW/Contents/Resources"
/usr/bin/codesign --force --deep --options runtime --sign "$IDENTITY" --identifier local.machealth.app "$NEW"
/usr/bin/codesign --verify --strict "$NEW"

if [ -d "$APP" ]; then chmod -R u+w "$APP"; fi
rm -rf "$APP"
mv "$NEW" "$APP"
echo "Built $APP"
if pgrep -x MacHealth >/dev/null; then
  echo "The old copy is still running. Quit it before opening the new one."
fi
