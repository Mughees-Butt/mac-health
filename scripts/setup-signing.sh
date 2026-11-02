#!/bin/zsh -f
# Creates the private "Mac Health Local Signing" key that build.sh signs with. Run once per Mac.
# A stable signature is what lets Full Disk Access survive rebuilds.
# The key isn't opened to any program, so macOS asks before each signing. Choose Allow, not Always Allow.
set -euo pipefail

NAME="Mac Health Local Signing"
KEYCHAIN="${1:-$HOME/Library/Keychains/login.keychain-db}"

if /usr/bin/security find-certificate -c "$NAME" "$KEYCHAIN" >/dev/null 2>&1; then
  echo "The $NAME key already exists, so nothing changed."
  exit 0
fi

umask 077
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/cert.conf" <<EOF
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

/usr/bin/openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -config "$WORK/cert.conf" \
  -keyout "$WORK/key.pem" -out "$WORK/cert.pem" 2>/dev/null
# This password only protects the temporary file on its way into the keychain.
PASSWORD="$(/usr/bin/openssl rand -hex 32)"
/usr/bin/openssl pkcs12 -export -inkey "$WORK/key.pem" -in "$WORK/cert.pem" -name "$NAME" \
  -out "$WORK/identity.p12" -passout "pass:$PASSWORD"
# -x means the private key can't be exported from the keychain afterwards.
/usr/bin/security import "$WORK/identity.p12" -k "$KEYCHAIN" -f pkcs12 -P "$PASSWORD" -x >/dev/null

echo "Created the $NAME key. Next, run ./build.sh"
