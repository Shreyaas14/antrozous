"""Secure Enclave key wrapping for macOS, via ctypes.

The enclave holds a P-256 key that CANNOT be exported — not by us, not by malware,
not by someone with the disk. We never ask it to sign or decrypt messages; we ask it
for one thing: a stable 32-byte secret that only exists on this machine. That secret
wraps `key.enc`, so the ed25519/x25519 material the rest of the gate uses is inert
bytes anywhere else.

Why not put the real keys in the enclave? It only does P-256. The message scheme is
ed25519 + x25519 end to end, and the gate has to decrypt unattended to render the
approval popup. So the enclave is a LOCK on the key file, not a replacement for it.

Deriving the secret:

    stored_public  = P-256 public key, generated once in software, private half
                     discarded immediately. Public halves are not secret.
    secret         = ECDH(enclave_private, stored_public)

Reproducible forever on this device, unreproducible anywhere else, and the enclave
private key never enters process memory.

ctypes rather than pyobjc so `python3 mcp_gate.py` keeps working with no install
step. Every entry point returns None or raises EnclaveError instead of exploding, so
a machine without an enclave falls back to the plain key file.
"""

import ctypes
import ctypes.util
import os
import platform
import sys

KEY_TAG = b"com.antrozous.wrap.v1"

# Touch ID on every gate start is opt-in. Without it the key is still enclave-bound
# and non-exportable — it just does not demand a fingerprint to use. That already
# defeats disk theft, which is the threat this module exists for.
REQUIRE_BIOMETRY = os.environ.get("ANTROZOUS_ENCLAVE_BIOMETRY", "0") == "1"


class EnclaveError(Exception):
    pass


def _load(name):
    path = ctypes.util.find_library(name)
    return ctypes.cdll.LoadLibrary(path) if path else None


_cf = _load("CoreFoundation")
_sec = _load("Security")

AVAILABLE_PLATFORM = (
    sys.platform == "darwin"
    and platform.machine() == "arm64"
    and _cf is not None
    and _sec is not None
)

if AVAILABLE_PLATFORM:
    CFTypeRef = ctypes.c_void_p
    CFIndex = ctypes.c_long

    _cf.CFRelease.argtypes = [CFTypeRef]
    _cf.CFRelease.restype = None
    _cf.CFStringCreateWithCString.argtypes = [
        CFTypeRef,
        ctypes.c_char_p,
        ctypes.c_uint32,
    ]
    _cf.CFStringCreateWithCString.restype = CFTypeRef
    _cf.CFDataCreate.argtypes = [CFTypeRef, ctypes.c_char_p, CFIndex]
    _cf.CFDataCreate.restype = CFTypeRef
    _cf.CFDataGetLength.argtypes = [CFTypeRef]
    _cf.CFDataGetLength.restype = CFIndex
    _cf.CFDataGetBytePtr.argtypes = [CFTypeRef]
    _cf.CFDataGetBytePtr.restype = ctypes.POINTER(ctypes.c_char)
    _cf.CFDictionaryCreateMutable.argtypes = [CFTypeRef, CFIndex, CFTypeRef, CFTypeRef]
    _cf.CFDictionaryCreateMutable.restype = CFTypeRef
    _cf.CFDictionarySetValue.argtypes = [CFTypeRef, CFTypeRef, CFTypeRef]
    _cf.CFDictionarySetValue.restype = None
    _cf.CFNumberCreate.argtypes = [CFTypeRef, CFIndex, ctypes.c_void_p]
    _cf.CFNumberCreate.restype = CFTypeRef

    _sec.SecKeyCreateRandomKey.argtypes = [CFTypeRef, ctypes.POINTER(CFTypeRef)]
    _sec.SecKeyCreateRandomKey.restype = CFTypeRef
    _sec.SecItemCopyMatching.argtypes = [CFTypeRef, ctypes.POINTER(CFTypeRef)]
    _sec.SecItemCopyMatching.restype = ctypes.c_int32
    _sec.SecKeyCopyPublicKey.argtypes = [CFTypeRef]
    _sec.SecKeyCopyPublicKey.restype = CFTypeRef
    _sec.SecKeyCopyExternalRepresentation.argtypes = [
        CFTypeRef,
        ctypes.POINTER(CFTypeRef),
    ]
    _sec.SecKeyCopyExternalRepresentation.restype = CFTypeRef
    _sec.SecKeyCreateWithData.argtypes = [
        CFTypeRef,
        CFTypeRef,
        ctypes.POINTER(CFTypeRef),
    ]
    _sec.SecKeyCreateWithData.restype = CFTypeRef
    _sec.SecKeyCopyKeyExchangeResult.argtypes = [
        CFTypeRef,
        CFTypeRef,
        CFTypeRef,
        CFTypeRef,
        ctypes.POINTER(CFTypeRef),
    ]
    _sec.SecKeyCopyKeyExchangeResult.restype = CFTypeRef
    # SecAccessControlCreateFlags is CFOptionFlags — 64-bit. Declaring it as uint32
    # corrupts the frame on arm64 and segfaults inside the enclave call.
    _sec.SecAccessControlCreateWithFlags.argtypes = [
        CFTypeRef,
        CFTypeRef,
        ctypes.c_ulong,
        ctypes.POINTER(CFTypeRef),
    ]
    _sec.SecAccessControlCreateWithFlags.restype = CFTypeRef

    # Dictionaries handed to Security must use the standard CF callbacks, or keys are
    # compared by raw pointer and lookups inside the framework miss.
    _KEY_CALLBACKS = ctypes.addressof(
        ctypes.c_void_p.in_dll(_cf, "kCFTypeDictionaryKeyCallBacks")
    )
    _VALUE_CALLBACKS = ctypes.addressof(
        ctypes.c_void_p.in_dll(_cf, "kCFTypeDictionaryValueCallBacks")
    )

    kCFAllocatorDefault = None
    kCFStringEncodingUTF8 = 0x08000100
    kCFNumberIntType = 9

    # SecAccessControlCreateFlags
    kSecAccessControlPrivateKeyUsage = 1 << 30
    kSecAccessControlBiometryCurrentSet = 1 << 3

    def _const(name):
        """Read an exported CFStringRef/SecKeyAlgorithm global out of the framework."""
        try:
            return CFTypeRef.in_dll(_sec, name)
        except ValueError:
            raise EnclaveError("Security.framework is missing %s" % name)

    def _cfstr(text):
        return _cf.CFStringCreateWithCString(
            kCFAllocatorDefault, text.encode(), kCFStringEncodingUTF8
        )

    def _cfdata(raw):
        return _cf.CFDataCreate(kCFAllocatorDefault, raw, len(raw))

    def _cfnum(value):
        holder = ctypes.c_int(value)
        return _cf.CFNumberCreate(
            kCFAllocatorDefault, kCFNumberIntType, ctypes.byref(holder)
        )

    def _cfdict(pairs):
        d = _cf.CFDictionaryCreateMutable(
            kCFAllocatorDefault, 0, _KEY_CALLBACKS, _VALUE_CALLBACKS
        )
        for key, value in pairs:
            _cf.CFDictionarySetValue(d, key, value)
        return d

    def _databytes(ref):
        length = _cf.CFDataGetLength(ref)
        return ctypes.string_at(_cf.CFDataGetBytePtr(ref), length)


def available():
    """True when this machine can actually hold an enclave key."""
    if not AVAILABLE_PLATFORM:
        return False
    try:
        _const("kSecAttrTokenIDSecureEnclave")
        return True
    except EnclaveError:
        return False


def _access_control():
    flags = kSecAccessControlPrivateKeyUsage
    if REQUIRE_BIOMETRY:
        # CurrentSet, not .biometryAny: adding a fingerprint later invalidates the
        # key rather than silently widening who can unwrap it.
        flags |= kSecAccessControlBiometryCurrentSet
    protection = _const("kSecAttrAccessibleWhenUnlockedThisDeviceOnly")
    err = ctypes.c_void_p()
    ref = _sec.SecAccessControlCreateWithFlags(
        kCFAllocatorDefault, protection, flags, ctypes.byref(err)
    )
    if not ref:
        raise EnclaveError("could not build an access control policy")
    return ref


def _find_key():
    query = _cfdict(
        [
            (_const("kSecClass"), _const("kSecClassKey")),
            (_const("kSecAttrApplicationTag"), _cfdata(KEY_TAG)),
            (
                _const("kSecAttrKeyType"),
                _const("kSecAttrKeyTypeECSECPrimeRandom"),
            ),
            (_const("kSecReturnRef"), _const("kCFBooleanTrue")),
        ]
    )
    out = ctypes.c_void_p()
    status = _sec.SecItemCopyMatching(query, ctypes.byref(out))
    _cf.CFRelease(query)
    return out if status == 0 and out else None


def _create_key():
    private_attrs = _cfdict(
        [
            (_const("kSecAttrIsPermanent"), _const("kCFBooleanTrue")),
            (_const("kSecAttrApplicationTag"), _cfdata(KEY_TAG)),
            (_const("kSecAttrAccessControl"), _access_control()),
        ]
    )
    attrs = _cfdict(
        [
            (_const("kSecAttrKeyType"), _const("kSecAttrKeyTypeECSECPrimeRandom")),
            (_const("kSecAttrKeySizeInBits"), _cfnum(256)),
            (_const("kSecAttrTokenID"), _const("kSecAttrTokenIDSecureEnclave")),
            (_const("kSecPrivateKeyAttrs"), private_attrs),
        ]
    )
    err = ctypes.c_void_p()
    key = _sec.SecKeyCreateRandomKey(attrs, ctypes.byref(err))
    _cf.CFRelease(attrs)
    if not key:
        raise EnclaveError("the Secure Enclave refused to create a key")
    return key


def _enclave_key():
    return _find_key() or _create_key()


def generate_peer_public():
    """A throwaway P-256 public key to ECDH against.

    Made in software and the private half is dropped on the floor — it is only a
    fixed point to derive against, never a secret. Storing it next to the wrapped
    blob is fine; on its own it unlocks nothing.
    """
    if not available():
        raise EnclaveError("no Secure Enclave on this machine")
    attrs = _cfdict(
        [
            (_const("kSecAttrKeyType"), _const("kSecAttrKeyTypeECSECPrimeRandom")),
            (_const("kSecAttrKeySizeInBits"), _cfnum(256)),
        ]
    )
    err = ctypes.c_void_p()
    private = _sec.SecKeyCreateRandomKey(attrs, ctypes.byref(err))
    _cf.CFRelease(attrs)
    if not private:
        raise EnclaveError("could not generate a peer keypair")
    public = _sec.SecKeyCopyPublicKey(private)
    _cf.CFRelease(private)
    if not public:
        raise EnclaveError("could not read the peer public key")
    raw = _sec.SecKeyCopyExternalRepresentation(public, ctypes.byref(err))
    _cf.CFRelease(public)
    if not raw:
        raise EnclaveError("could not export the peer public key")
    out = _databytes(raw)
    _cf.CFRelease(raw)
    return out


def wrapping_secret(peer_public_raw):
    """The 32-byte secret this device — and only this device — can reproduce.

    Prompts for Touch ID when ANTROZOUS_ENCLAVE_BIOMETRY=1.
    """
    if not available():
        raise EnclaveError("no Secure Enclave on this machine")
    attrs = _cfdict(
        [
            (_const("kSecAttrKeyType"), _const("kSecAttrKeyTypeECSECPrimeRandom")),
            (_const("kSecAttrKeyClass"), _const("kSecAttrKeyClassPublic")),
        ]
    )
    err = ctypes.c_void_p()
    peer = _sec.SecKeyCreateWithData(_cfdata(peer_public_raw), attrs, ctypes.byref(err))
    _cf.CFRelease(attrs)
    if not peer:
        raise EnclaveError("stored peer public key is unusable")

    private = _enclave_key()
    params = _cfdict([])
    shared = _sec.SecKeyCopyKeyExchangeResult(
        private,
        _const("kSecKeyAlgorithmECDHKeyExchangeStandard"),
        peer,
        params,
        ctypes.byref(err),
    )
    _cf.CFRelease(peer)
    _cf.CFRelease(params)
    if not shared:
        raise EnclaveError(
            "the Secure Enclave refused the key exchange "
            "(cancelled Touch ID, or the key was invalidated)"
        )
    out = _databytes(shared)
    _cf.CFRelease(shared)
    if len(out) < 32:
        raise EnclaveError("key exchange returned %d bytes" % len(out))
    return out


def describe():
    return {
        "available": available(),
        "platform": "%s/%s" % (sys.platform, platform.machine()),
        "biometry": REQUIRE_BIOMETRY,
    }
