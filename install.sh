#!/bin/zsh -f
# Sets up Mac Health on this Mac from a fresh clone: checks what it needs, creates your private signing key,
# builds and signs the app, adds the machealth command, then opens Full Disk Access settings for you.
# Safe to run again. Nothing here needs your admin password.
#   ./install.sh          set everything up
#   ./install.sh --check  only report what's missing, changing nothing
set -euo pipefail
cd "${0:A:h}"

CHECK_ONLY=0
case "${1:-}" in
  "") ;;
  --check) CHECK_ONLY=1 ;;
  -h|--help) print "Usage: ./install.sh [--check]"; exit 0 ;;
  *) print -u2 "Unknown option: $1. Try ./install.sh --help."; exit 2 ;;
esac

ok() { print "  ✓ $1"; }
missing() { print -u2 "  ✗ $1"; }
problems=0

print "Checking this Mac"
major="$(/usr/bin/sw_vers -productVersion | /usr/bin/cut -d. -f1)"
if [ "$major" -ge 13 ]; then ok "macOS $(/usr/bin/sw_vers -productVersion)"; else missing "macOS 13 or later is needed"; problems=1; fi

# The app runs only the root-owned Python these tools install, so Xcode alone isn't enough.
python="/Library/Developer/CommandLineTools/usr/bin/python3"
if [ -x "$python" ] && [ "$(/usr/bin/stat -f %u "$python")" = 0 ] && [ -x /usr/bin/swiftc ]; then
  ok "Command Line Tools"
else
  missing "Command Line Tools. Install them with: xcode-select --install, then run this again"
  problems=1
fi

if [ -f .signing-identity ]; then ok "Signing key"
elif /usr/bin/security find-certificate -c "Mac Health Local Signing" >/dev/null 2>&1; then
  missing "A key named Mac Health Local Signing exists that this setup didn't make. Run ./scripts/setup-signing.sh to see how to replace it"
  problems=1
else print "  • Signing key: will be created"; fi
if [ -d "Mac Health.app" ]; then print "  • App: will be rebuilt"; else print "  • App: will be built"; fi

LINK="$HOME/.local/bin/machealth"
TARGET="$PWD/bin/machealth"
if [ -L "$LINK" ] && [ "$(/usr/bin/readlink "$LINK")" = "$TARGET" ]; then ok "machealth command"
elif [ -e "$LINK" ] || [ -L "$LINK" ]; then print "  • machealth command: $LINK points elsewhere, so it will be left alone"
else print "  • machealth command: will be added to ~/.local/bin"; fi

if [ "$problems" = 1 ]; then print -u2 "\nFix the items marked ✗, then run ./install.sh again."; exit 1; fi
if [ "$CHECK_ONLY" = 1 ]; then print "\nReady. Run ./install.sh to set it up."; exit 0; fi

print "\nmacOS will ask to use your new signing key while building."
print "Choose Allow, not Always Allow, so nothing can sign silently."
print "Mac Health will also ask once to keep its encryption key. Allow that for Mac Health.\n"

./scripts/setup-signing.sh
./build.sh

if [ ! -e "$LINK" ] && [ ! -L "$LINK" ]; then
  /bin/mkdir -p "${LINK:h}"
  /bin/ln -s "$TARGET" "$LINK"
  ok "Added $LINK"
fi
case ":$PATH:" in
  *":$HOME/.local/bin:"*) ;;
  *) print "  • Add ~/.local/bin to your PATH to use machealth anywhere: echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.zshrc" ;;
esac

/usr/bin/open -R "$PWD/Mac Health.app"
/usr/bin/open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
print "\nLast step: Full Disk Access"
print "  1. In the Settings window that just opened, click + or drag in Mac Health from the Finder window."
print "  2. Turn it on, then run: machealth"
print "     (or open Mac Health.app). It works without this step, but can't see protected folders."
