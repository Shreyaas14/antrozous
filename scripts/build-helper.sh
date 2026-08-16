#!/usr/bin/env bash
# Build and sign antrozous-helper, the entitled binary that can persist a Secure
# Enclave key. Everything else in antrozous runs on bare python3; this is the one
# piece macOS refuses to let an unsigned process do.
#
#   ./scripts/build-helper.sh
#
# Needs Xcode command line tools and an Apple ID signed into Xcode. A free
# personal team is enough to run it on YOUR machines. Distributing a prebuilt
# binary to someone else needs a paid Developer ID and notarisation -- but anyone
# with Xcode can just run this themselves instead.
#
# Optional and unset by default:
#   ANTROZOUS_ENCLAVE_BIOMETRY=1   require Touch ID to use the key
set -euo pipefail

cd "$(dirname "$0")/.."
OUT="${ANTROZOUS_HELPER_DIR:-$HOME/.antrozous}/antrozous-helper"

if ! command -v swiftc >/dev/null 2>&1 && ! xcrun -f swiftc >/dev/null 2>&1; then
    echo "error: swiftc not found. Install Xcode command line tools:" >&2
    echo "    xcode-select --install" >&2
    exit 1
fi

# Pick the first Apple Development identity. Anything self-signed is useless here:
# keychain-access-groups must be prefixed with a team identifier Apple issued, and
# macOS checks the prefix against the signing certificate's team.
IDENTITY=$(security find-identity -v -p codesigning 2>/dev/null \
    | grep -o '"Apple Development: [^"]*"' | head -1 | tr -d '"')

if [ -z "$IDENTITY" ]; then
    cat >&2 <<'EOF'
error: no Apple Development signing identity found.

Without one macOS refuses to persist the enclave key (errSecMissingEntitlement,
-34018) and the helper is useless. To create one, free:

  Xcode -> Settings -> Accounts -> + -> sign in with your Apple ID
  select the account -> Manage Certificates... -> + -> Apple Development

Then re-run this script. antrozous works fine without it; you just keep the
plain key file instead of an enclave-wrapped one.
EOF
    exit 1
fi
echo "signing identity: $IDENTITY"

# The team id is the OU field of the certificate. codesign will not substitute
# $(AppIdentifierPrefix) for us the way an Xcode build would, so bake it in.
CERT_NAME=${IDENTITY#Apple Development: }
TEAM=$(security find-certificate -c "$IDENTITY" -p 2>/dev/null \
    | openssl x509 -noout -subject 2>/dev/null \
    | tr ',/' '\n\n' | awk -F= '/OU[ ]*=/ {gsub(/ /,"",$2); print $2}' | head -1)

if [ -z "$TEAM" ]; then
    echo "error: could not read the team id from certificate '$CERT_NAME'" >&2
    exit 1
fi
echo "team id: $TEAM"

BUILD=$(mktemp -d)
trap 'rm -rf "$BUILD"' EXIT

cat > "$BUILD/helper.entitlements" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>keychain-access-groups</key>
    <array>
        <string>$TEAM.com.antrozous.helper</string>
    </array>
</dict>
</plist>
EOF

mkdir -p "$(dirname "$OUT")"
xcrun swiftc -O -o "$BUILD/antrozous-helper" helper/helper.swift
codesign --force --options runtime \
    --entitlements "$BUILD/helper.entitlements" \
    --sign "$IDENTITY" "$BUILD/antrozous-helper"
mv "$BUILD/antrozous-helper" "$OUT"

echo "built: $OUT"
echo
echo "verifying the entitlement actually took..."
if "$OUT" check; then
    echo "the enclave accepted a persistent key -- Touch ID wrapping is available."
else
    echo "the helper built but the enclave still refused. The signature is probably" >&2
    echo "missing the entitlement; check: codesign -d --entitlements - $OUT" >&2
    exit 1
fi
