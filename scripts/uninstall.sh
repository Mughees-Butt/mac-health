#!/bin/zsh -f
# Removes Mac Health from this Mac. It asks before each step, and removes nothing it doesn't name.
set -euo pipefail
cd "${0:A:h:h}"

ask() { read -q "?$1 [y/N] " && print || { print; return 1; }; }

if /usr/bin/pgrep -x MacHealth >/dev/null; then print -u2 "Quit Mac Health first (Mac Health > Quit Mac Health), then run this again."; exit 1; fi

LINK="$HOME/.local/bin/machealth"
if [ -L "$LINK" ] && [ "$(/usr/bin/readlink "$LINK")" = "$PWD/bin/machealth" ] && ask "Remove the machealth command?"; then /bin/rm "$LINK"; fi
if [ -d "Mac Health.app" ] && ask "Remove the built Mac Health.app?"; then /bin/chmod -R u+w "Mac Health.app"; /bin/rm -rf "Mac Health.app"; fi
if [ -d "$HOME/.mac-health" ] && [ ! -L "$HOME/.mac-health" ] && ask "Delete your saved results and history in ~/.mac-health?"; then /bin/rm -rf "$HOME/.mac-health"; fi
if /usr/bin/security find-generic-password -s local.machealth.data-key >/dev/null 2>&1 && ask "Delete the 'Mac Health saved results' keychain item?"; then
  /usr/bin/security delete-generic-password -s local.machealth.data-key >/dev/null
fi
if /usr/bin/security find-certificate -c "Mac Health Local Signing" >/dev/null 2>&1 && ask "Delete the 'Mac Health Local Signing' key?"; then
  /usr/bin/security delete-identity -c "Mac Health Local Signing" >/dev/null
fi
print "\nTo finish, remove Mac Health from System Settings > Privacy & Security > Full Disk Access."
