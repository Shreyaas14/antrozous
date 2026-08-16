"""Ed25519 identity keys and X25519 sealed boxes.

Uses `cryptography` when importable and falls back to vendored pure-Python
primitives otherwise, so the plugin runs on bare python3. Both backends produce
identical bytes on the wire.

identity.py never imports this, so the SessionStart hook stays crypto-free.
"""

import base64
import hashlib
import json
import os
import sys
import time

import identity

KEY_VERSION = 1
SEAL_VERSION = b"\x01"
_SEAL_INFO = b"antrozous-seal-v1"
FINGERPRINT_CHARS = 8

# Relay request auth. Must stay byte-identical to the server's copy in server.py.
AUTH_SCHEME = "Antrozous"
AUTH_CONTEXT = "antrozous-auth-v1"


class CryptoError(Exception):
    pass


# ---------- backend ----------
try:
    from cryptography.hazmat.primitives import serialization as _ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.exceptions import InvalidSignature

    BACKEND = "cryptography"

    def _raw_public(key):
        return key.public_bytes(
            encoding=_ser.Encoding.Raw, format=_ser.PublicFormat.Raw
        )

    def _ed_public_from_seed(seed):
        return _raw_public(Ed25519PrivateKey.from_private_bytes(seed).public_key())

    def _ed_sign(seed, message):
        return Ed25519PrivateKey.from_private_bytes(seed).sign(message)

    def _ed_verify(public, signature, message):
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
            return True
        except (InvalidSignature, ValueError):
            return False

    def _x_public_from_scalar(scalar):
        return _raw_public(X25519PrivateKey.from_private_bytes(scalar).public_key())

    def _x_exchange(scalar, peer_public):
        return X25519PrivateKey.from_private_bytes(scalar).exchange(
            X25519PublicKey.from_public_bytes(peer_public)
        )

    def _aead_encrypt(key, nonce, plaintext, aad):
        return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)

    def _aead_decrypt(key, nonce, ciphertext, aad):
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)

    def _hkdf(ikm, info, length=32):
        return HKDF(algorithm=SHA256(), length=length, salt=None, info=info).derive(ikm)

except ImportError:
    import _purecrypto as _pc

    BACKEND = "pure-python"

    def _ed_public_from_seed(seed):
        return _pc.ed25519_public_from_seed(seed)

    def _ed_sign(seed, message):
        return _pc.ed25519_sign(seed, message)

    def _ed_verify(public, signature, message):
        try:
            return _pc.ed25519_verify(public, signature, message)
        except ValueError:
            return False

    def _x_public_from_scalar(scalar):
        return _pc.x25519_public_from_scalar(scalar)

    def _x_exchange(scalar, peer_public):
        return _pc.x25519(scalar, peer_public)

    def _aead_encrypt(key, nonce, plaintext, aad):
        return _pc.chacha20poly1305_encrypt(key, nonce, plaintext, aad)

    def _aead_decrypt(key, nonce, ciphertext, aad):
        return _pc.chacha20poly1305_decrypt(key, nonce, ciphertext, aad)

    def _hkdf(ikm, info, length=32):
        return _pc.hkdf_sha256(ikm, length=length, salt=None, info=info)


# ---------- key material ----------
def key_path():
    return os.path.join(identity.global_dir(), "key.json")


def wrapped_path():
    return os.path.join(identity.global_dir(), "key.enc")


def helper_path():
    """The signed bundle that can talk to the Secure Enclave.

    Built by scripts/build-helper.sh. Absent on Linux, on Macs without Xcode, and
    on any machine where nobody has opted in — all of which fall back to the plain
    key file rather than failing.
    """
    return os.path.join(
        identity.global_dir(),
        "AntrozousHelper.app",
        "Contents",
        "MacOS",
        "AntrozousHelper",
    )


def _helper(*args):
    """Run the helper. Returns its stdout, or None if it is unavailable.

    Never raises: every caller has a working fallback, and an enclave that is
    missing, cancelled or broken must degrade to the key file rather than locking
    someone out of their own identity.
    """
    binary = helper_path()
    if not os.path.exists(binary):
        return None
    try:
        import subprocess

        out = subprocess.run(
            [binary] + list(args), capture_output=True, text=True, timeout=120
        )
    except (OSError, ValueError) as e:
        raise CryptoError("could not run the enclave helper: %s" % e)
    if out.returncode != 0:
        raise CryptoError((out.stderr or out.stdout or "").strip() or "helper failed")
    return out.stdout.strip()


def _wrap_key(secret):
    return _hkdf(secret, b"antrozous-wrap-v1")


def enclave_available():
    return os.path.exists(helper_path())


def enclave_load():
    """Unwrap key.enc using the enclave, or None if that is not possible.

    Prompts for Touch ID when the helper was built with biometry required.
    """
    blob = identity._read_json(wrapped_path())
    if not (blob and blob.get("peer") and blob.get("sealed")):
        return None
    secret = _helper("derive", blob["peer"])
    if not secret:
        return None
    nonce, ct = _unb64(blob["sealed"])[:12], _unb64(blob["sealed"])[12:]
    try:
        raw = _aead_decrypt(_wrap_key(_unb64(secret)), nonce, ct, b"antrozous-wrap-v1")
    except Exception as e:
        raise CryptoError(
            "key.enc did not decrypt (%s). The enclave key was probably reset or "
            "the Touch ID enrolment changed, which destroys the wrapping key." % e
        )
    return json.loads(raw.decode())


def enclave_wrap(record=None):
    """Write key.enc from the current keys. Leaves key.json alone.

    Deliberately non-destructive: while both files exist the enclave path can be
    tested and abandoned freely. Removing key.json is the separate step that makes
    the protection real, and the point of no return if the enclave is ever lost.
    """
    if not enclave_available():
        raise CryptoError(
            "no enclave helper at %s — run scripts/build-helper.sh" % helper_path()
        )
    record = record or load_or_create()
    peer = _helper("init")
    secret = _helper("derive", peer)
    nonce = os.urandom(12)
    plaintext = json.dumps(
        {
            "version": record.get("version", KEY_VERSION),
            "ed25519_private": record["ed25519_private"],
            "x25519_private": record["x25519_private"],
        }
    ).encode()
    sealed = nonce + _aead_encrypt(
        _wrap_key(_unb64(secret)), nonce, plaintext, b"antrozous-wrap-v1"
    )
    path = wrapped_path()
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"peer": peer, "sealed": _b64(sealed)}, f)
    os.replace(tmp, path)
    return path


def _b64(raw):
    return base64.b64encode(raw).decode()


def _unb64(text):
    if not isinstance(text, str):
        raise CryptoError("expected base64 text")
    try:
        return base64.b64decode(text.encode(), validate=True)
    except Exception as e:
        raise CryptoError("bad base64: %s" % e)


def fingerprint(ed25519_public_raw):
    """Short, id-legal digest of an identity key.

    base32 lowercased lands in [a-z2-7], already legal in an agent id. Two users who
    pick the same name still differ here, which is what stops one person's messages
    reaching the other's inbox.
    """
    digest = hashlib.sha256(ed25519_public_raw).digest()
    return base64.b32encode(digest).decode().lower()[:FINGERPRINT_CHARS]


def generate():
    return {
        "version": KEY_VERSION,
        "ed25519_private": _b64(os.urandom(32)),
        "x25519_private": _b64(os.urandom(32)),
    }


def _valid(record):
    return bool(
        record and record.get("ed25519_private") and record.get("x25519_private")
    )


# Unwrapped once per process. The gate has to decrypt unattended to render the
# approval popup, so asking the enclave per operation would mean a fingerprint per
# doorbell — including at 3am. One tap per gate start is the only bearable
# granularity, and it means the keys live in memory for the session either way.
_unwrapped = None


def load_or_create():
    """This device's keys, from the enclave-wrapped file if there is one.

    Order matters: wrapped first, plaintext second. While both exist the plaintext
    is a deliberate fallback — you can test the enclave path without being able to
    lock yourself out. Deleting key.json is the separate, irreversible step that
    actually buys protection against someone holding your disk.
    """
    global _unwrapped
    if _valid(_unwrapped):
        return _unwrapped

    path = key_path()
    try:
        record = enclave_load()
    except CryptoError as e:
        # An unopenable key.enc must NEVER strand you while a plaintext key still
        # exists — a stale wrap (enclave reset, Touch ID re-enrolled) would
        # otherwise brick the gate even though the identity is sitting on disk.
        # Only once key.json is gone is this genuinely fatal.
        if not _valid(identity._read_json(path)):
            raise
        print(
            "[antrozous-keys] key.enc could not be opened (%s); falling back to "
            "key.json. Re-wrap with keys.enclave_wrap() to use the enclave again." % e,
            file=sys.stderr,
        )
        record = None
    if _valid(record):
        _unwrapped = record
        return record

    record = identity._read_json(path)
    if _valid(record):
        return record
    os.makedirs(identity.global_dir(), exist_ok=True)
    record = generate()
    try:
        # O_EXCL so two gates starting together cannot clobber each other's key;
        # the loser reads the winner's file instead of overwriting it.
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(record, f)
        return record
    except FileExistsError:
        existing = identity._read_json(path)
        if not _valid(existing):
            raise CryptoError("key file at %s is unreadable" % path)
        return existing


def _seed(record):
    seed = _unb64(record["ed25519_private"])
    if len(seed) != 32:
        raise CryptoError("ed25519 seed must be 32 bytes")
    return seed


def _scalar(record):
    scalar = _unb64(record["x25519_private"])
    if len(scalar) != 32:
        raise CryptoError("x25519 scalar must be 32 bytes")
    return scalar


def public_bundle(record=None):
    """The public half others need: {ed25519, x25519, fingerprint}."""
    record = record or load_or_create()
    ed_pub = _ed_public_from_seed(_seed(record))
    return {
        "ed25519": _b64(ed_pub),
        "x25519": _b64(_x_public_from_scalar(_scalar(record))),
        "fingerprint": fingerprint(ed_pub),
    }


def my_fingerprint():
    return public_bundle()["fingerprint"]


def sign(data, record=None):
    record = record or load_or_create()
    return _b64(_ed_sign(_seed(record), data))


def verify(ed25519_public_b64, signature_b64, data):
    try:
        public, signature = _unb64(ed25519_public_b64), _unb64(signature_b64)
    except CryptoError:
        return False
    if len(public) != 32 or len(signature) != 64:
        return False
    return _ed_verify(public, signature, data)


def auth_bytes(method, path, agent_id, ts, nonce):
    """Canonical bytes covering a relay request. Mirrors server.auth_bytes exactly."""
    return "\n".join([AUTH_CONTEXT, method.upper(), path, agent_id, ts, nonce]).encode()


def auth_header(agent_id, method, path, record=None):
    """Prove possession of this device's identity key for one request.

    The public key travels with the signature so the relay can check it against the
    fingerprint in `agent_id` without a directory lookup — the address itself is the
    assertion. `path` must include the query string, or a consume's `count` would
    not be covered.
    """
    record = record or load_or_create()
    ts = "%d" % int(time.time())
    nonce = base64.b16encode(os.urandom(12)).decode().lower()
    signature = sign(auth_bytes(method, path, agent_id, ts, nonce), record)
    return "%s %s:%s:%s:%s:%s" % (
        AUTH_SCHEME,
        agent_id,
        ts,
        nonce,
        public_bundle(record)["ed25519"],
        signature,
    )


def _seal_key(shared, eph_pub, recipient_pub):
    return _hkdf(shared + eph_pub + recipient_pub, _SEAL_INFO)


def seal(recipient_x25519_b64, plaintext, aad=b""):
    """Anonymous sealed box with a fresh ephemeral key per message.

    The ephemeral private key is discarded here, so compromising the SENDER later
    reveals nothing about what it sent.
    """
    recipient_pub = _unb64(recipient_x25519_b64)
    if len(recipient_pub) != 32:
        raise CryptoError("recipient x25519 key must be 32 bytes")
    eph_scalar = os.urandom(32)
    eph_pub = _x_public_from_scalar(eph_scalar)
    shared = _x_exchange(eph_scalar, recipient_pub)
    nonce = os.urandom(12)
    ct = _aead_encrypt(_seal_key(shared, eph_pub, recipient_pub), nonce, plaintext, aad)
    return _b64(SEAL_VERSION + eph_pub + nonce + ct)


def unseal(blob_b64, record=None, aad=b""):
    record = record or load_or_create()
    blob = _unb64(blob_b64)
    if len(blob) < 1 + 32 + 12 + 16:
        raise CryptoError("sealed box too short")
    if blob[:1] != SEAL_VERSION:
        raise CryptoError("unsupported seal version %d" % blob[0])
    eph_pub, nonce, ct = blob[1:33], blob[33:45], blob[45:]
    scalar = _scalar(record)
    shared = _x_exchange(scalar, eph_pub)
    key = _seal_key(shared, eph_pub, _x_public_from_scalar(scalar))
    try:
        return _aead_decrypt(key, nonce, ct, aad)
    except Exception as e:
        raise CryptoError("decryption failed: %s" % e)
