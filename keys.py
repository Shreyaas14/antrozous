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


def load_or_create():
    path = key_path()
    record = identity._read_json(path)
    if record and record.get("ed25519_private") and record.get("x25519_private"):
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
        if not (existing and existing.get("ed25519_private")):
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
