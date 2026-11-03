#!/bin/zsh -f
# Creates the private "Mac Health Local Signing" key that build.sh signs with. Run once per Mac.
# A stable signature is what lets Full Disk Access survive rebuilds.
# The key it creates is recorded in .signing-identity, and build.sh signs with that exact key only, so a key with the
# same name made by anything else, for example planted before you installed, is never used.
set -euo pipefail
# A clean environment, so tools found through your PATH can't see the key being made.
if [ "${MAC_HEALTH_CLEAN_SETUP:-}" != "$$" ]; then
  exec /usr/bin/env -i HOME="$HOME" PATH=/usr/bin:/bin:/usr/sbin:/sbin LANG=en_US.UTF-8 MAC_HEALTH_CLEAN_SETUP="$$" /bin/zsh -f "$0" "$@"
fi

NAME="Mac Health Local Signing"
KEYCHAIN="$HOME/Library/Keychains/login.keychain-db"
cd "${0:A:h:h}"
PIN=".signing-identity"
fingerprints() { /usr/bin/security find-certificate -a -c "$NAME" -Z "$KEYCHAIN" 2>/dev/null | /usr/bin/awk '/SHA-1/{print $3}'; }

if [ -f "$PIN" ] && fingerprints | /usr/bin/grep -qx "$(/bin/cat "$PIN")"; then
  echo "The $NAME key is already set up, so nothing changed."
  exit 0
fi
# An existing key can't be trusted: older versions made keys any program could copy, and one could be planted.
existing=("${(@f)$(fingerprints)}")
if [ -n "${existing[1]:-}" ]; then
  echo "A key named $NAME already exists that this setup didn't make, so it won't be used." >&2
  echo "Delete it, then run this again. You'll need to turn on Full Disk Access for Mac Health once more afterwards:" >&2
  for fp in "${existing[@]}"; do echo "  security delete-identity -Z $fp" >&2; done
  exit 1
fi

umask 077
WORK="$(/usr/bin/mktemp -d)"
trap '/bin/rm -rf "$WORK"' EXIT

/bin/cat > "$WORK/cert.conf" <<EOF
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = $NAME
[ext]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, codeSigning
EOF

# The private key only ever travels through pipes, never a file. The password protects nothing on disk.
KEY="$(/usr/bin/openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 2>/dev/null)"
print -r -- "$KEY" | /usr/bin/openssl req -x509 -new -key /dev/stdin -days 3650 -config "$WORK/cert.conf" -out "$WORK/cert.pem" 2>/dev/null
PASSWORD="$(/usr/bin/openssl rand -hex 32)"
# Tested: -x alone still lets any program run `security export` silently, because the importing tool stays trusted.
# Naming a harmless program as the only trusted one means both exporting and signing need your approval.
print -r -- "$KEY" | /usr/bin/openssl pkcs12 -export -inkey /dev/stdin -in "$WORK/cert.pem" -name "$NAME" -passout file:/dev/fd/3 3< <(print -r -- "$PASSWORD") \
  | /usr/bin/security import /dev/stdin -k "$KEYCHAIN" -f pkcs12 -P "$PASSWORD" -x -T /usr/bin/true >/dev/null
KEY=""
/usr/bin/openssl x509 -in "$WORK/cert.pem" -noout -fingerprint -sha1 | /usr/bin/sed 's/.*=//; s/://g' > "$PIN"

echo "Created the $NAME key. Next, run ./build.sh"
