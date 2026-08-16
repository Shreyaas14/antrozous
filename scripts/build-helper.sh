#!/usr/bin/env bash
# Build AntrozousHelper.app — the entitled bundle that can hold a Secure Enclave
# key. Everything else in antrozous runs on bare python3; this is the one piece
# macOS refuses to let an unsigned process do.
#
#   ./scripts/build-helper.sh
#   ANTROZOUS_ENCLAVE_BIOMETRY=1 ./scripts/build-helper.sh   # require Touch ID
#
# Why an .app and not a plain signed binary: keychain-access-groups is a RESTRICTED
# entitlement. macOS kills the process at exec unless a provisioning profile
# authorises it, and a bare Mach-O has nowhere to carry one — profiles live at
# Contents/embedded.provisionprofile inside a bundle. So this goes through
# xcodebuild, which is also what creates the profile in the first place.
#
# Needs Xcode and an Apple ID signed into it. A free personal team is enough for
# your own machines; the paid Developer ID is only for shipping a prebuilt bundle
# to someone who will not build it themselves.
set -euo pipefail

cd "$(dirname "$0")/.."
DEST="${ANTROZOUS_HELPER_DIR:-$HOME/.antrozous}"
DERIVED="${TMPDIR:-/tmp}/antrozous-helper-build"

if ! xcrun -f xcodebuild >/dev/null 2>&1; then
    echo "error: xcodebuild not found. Install Xcode, then:" >&2
    echo "    sudo xcode-select -s /Applications/Xcode.app" >&2
    exit 1
fi

if ! security find-identity -v -p codesigning 2>/dev/null | grep -q "Apple Development"; then
    cat >&2 <<'EOF'
error: no Apple Development signing identity.

Create one free: Xcode -> Settings -> Accounts -> + -> sign in with your Apple ID,
then select the account -> Manage Certificates... -> + -> Apple Development.

antrozous works fine without this. You keep the plain 0600 key file instead of an
enclave-wrapped one, which still stops anyone who only knows your agent id -- it
just does not protect the key if someone gets your disk.
EOF
    exit 1
fi

# -allowProvisioningUpdates lets Xcode register this Mac and mint the profile that
# authorises the entitlement. The FIRST run does that work and is slow; later runs
# are quick.
echo "building (first run also provisions, which takes a while)..."
xcrun xcodebuild \
    -project helper/AntrozousHelper.xcodeproj \
    -scheme AntrozousHelper \
    -configuration Release \
    -derivedDataPath "$DERIVED" \
    -allowProvisioningUpdates \
    build >"$DERIVED.log" 2>&1 || {
        echo "build failed; last 20 lines:" >&2
        tail -20 "$DERIVED.log" >&2
        exit 1
    }

APP="$DERIVED/Build/Products/Release/AntrozousHelper.app"
if [ ! -d "$APP/Contents/embedded.provisionprofile" ] && [ ! -f "$APP/Contents/embedded.provisionprofile" ]; then
    echo "error: built, but no provisioning profile was embedded." >&2
    echo "Without one macOS kills the helper at exec. Open the project in Xcode" >&2
    echo "once and let it resolve signing: open helper/AntrozousHelper.xcodeproj" >&2
    exit 1
fi

mkdir -p "$DEST"
rm -rf "$DEST/AntrozousHelper.app"
cp -R "$APP" "$DEST/AntrozousHelper.app"
BIN="$DEST/AntrozousHelper.app/Contents/MacOS/AntrozousHelper"
echo "installed: $DEST/AntrozousHelper.app"

echo
echo "verifying the enclave actually accepts a persistent key..."
if OUT=$("$BIN" check 2>&1); then
    echo "  $OUT"
    echo "enclave key wrapping is available."
else
    echo "  $OUT" >&2
    echo "the bundle built but the enclave refused. -34018 means the entitlement" >&2
    echo "is not authorised; check: codesign -d --entitlements - '$BIN'" >&2
    exit 1
fi
