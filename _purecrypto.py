"""Pure-Python Ed25519, X25519, ChaCha20-Poly1305 and HKDF-SHA256.

Fallback for machines without `cryptography`, so the plugin keeps working on bare
python3. Byte-for-byte wire-compatible with the cryptography backend: raw Ed25519
seeds and X25519 scalars, RFC 8032 signatures, RFC 8439 AEAD, RFC 5869 HKDF.

NOT constant-time. Adequate against a passive relay operator reading stored bytes;
weaker than libsodium against an attacker timing this process locally.
"""

import hashlib
import hmac as _hmac

# ---------- field arithmetic (curve25519) ----------
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, P - 2, P)


_D = (-121665 * _inv(121666)) % P
_I = pow(2, (P - 1) // 4, P)


# ---------- Ed25519 (RFC 8032) ----------
def _x_recover(y):
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * _I) % P
    if x % 2 != 0:
        x = P - x
    return x


_BY = (4 * _inv(5)) % P
_BX = _x_recover(_BY)
# Extended coordinates (X, Y, Z, T) with T = XY/Z; avoids an inversion per add.
_B = (_BX, _BY, 1, (_BX * _BY) % P)


def _ed_add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % P
    b = ((y1 + x1) * (y2 + x2)) % P
    c = (2 * t1 * t2 * _D) % P
    dd = (2 * z1 * z2) % P
    e, f, g, h = (b - a) % P, (dd - c) % P, (dd + c) % P, (b + a) % P
    return ((e * f) % P, (g * h) % P, (f * g) % P, (e * h) % P)


def _ed_double(p):
    return _ed_add(p, p)


def _ed_scalarmult(point, e):
    result = (0, 1, 1, 0)
    while e > 0:
        if e & 1:
            result = _ed_add(result, point)
        point = _ed_double(point)
        e >>= 1
    return result


def _ed_affine(p):
    x, y, z, _ = p
    zi = _inv(z)
    return (x * zi) % P, (y * zi) % P


def _encode_point(p):
    x, y = _ed_affine(p)
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode_point(raw):
    if len(raw) != 32:
        raise ValueError("bad point length")
    value = int.from_bytes(raw, "little")
    y = value & ((1 << 255) - 1)
    sign = value >> 255
    if y >= P:
        raise ValueError("non-canonical point")
    x = _x_recover(y)
    if x & 1 != sign:
        x = P - x
    point = (x, y, 1, (x * y) % P)
    if not _on_curve(point):
        raise ValueError("point not on curve")
    return point


def _on_curve(p):
    x, y = _ed_affine(p)
    return (-x * x + y * y - 1 - _D * x * x * y * y) % P == 0


def _ed_equal(a, b):
    return _ed_affine(a) == _ed_affine(b)


def _sha512(data):
    return hashlib.sha512(data).digest()


def _clamp_ed_scalar(h):
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a


def ed25519_public_from_seed(seed):
    if len(seed) != 32:
        raise ValueError("ed25519 seed must be 32 bytes")
    return _encode_point(_ed_scalarmult(_B, _clamp_ed_scalar(_sha512(seed))))


def ed25519_sign(seed, message):
    h = _sha512(seed)
    a = _clamp_ed_scalar(h)
    public = _encode_point(_ed_scalarmult(_B, a))
    r = int.from_bytes(_sha512(h[32:] + message), "little") % L
    big_r = _encode_point(_ed_scalarmult(_B, r))
    k = int.from_bytes(_sha512(big_r + public + message), "little") % L
    s = (r + k * a) % L
    return big_r + s.to_bytes(32, "little")


def ed25519_verify(public, signature, message):
    if len(signature) != 64 or len(public) != 32:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        # Reject non-canonical S; otherwise signatures are malleable.
        return False
    try:
        big_r = _decode_point(signature[:32])
        point_a = _decode_point(public)
    except ValueError:
        return False
    k = int.from_bytes(_sha512(signature[:32] + public + message), "little") % L
    left = _ed_scalarmult(_B, s)
    right = _ed_add(big_r, _ed_scalarmult(point_a, k))
    return _ed_equal(left, right)


# ---------- X25519 (RFC 7748) ----------
_A24 = 121665


def _clamp_x_scalar(raw):
    k = bytearray(raw)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")


def x25519(scalar, u_raw):
    if len(scalar) != 32 or len(u_raw) != 32:
        raise ValueError("x25519 inputs must be 32 bytes")
    k = _clamp_x_scalar(scalar)
    u = int.from_bytes(u_raw, "little") & ((1 << 255) - 1)
    x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        if swap != kt:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % P
        aa = (a * a) % P
        b = (x2 - z2) % P
        bb = (b * b) % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = (d * a) % P
        cb = (c * b) % P
        x3 = pow((da + cb) % P, 2, P)
        z3 = (x1 * pow((da - cb) % P, 2, P)) % P
        x2 = (aa * bb) % P
        z2 = (e * ((aa + _A24 * e) % P)) % P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    shared = (x2 * _inv(z2)) % P
    return shared.to_bytes(32, "little")


def x25519_public_from_scalar(scalar):
    base = (9).to_bytes(32, "little")
    return x25519(scalar, base)


# ---------- ChaCha20-Poly1305 (RFC 8439) ----------
def _rotl32(v, c):
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def _quarter_round(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl32(s[b] ^ s[c], 7)


_CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)


def _chacha20_block(key, counter, nonce):
    state = list(_CONSTANTS)
    state += [int.from_bytes(key[i : i + 4], "little") for i in range(0, 32, 4)]
    state.append(counter & 0xFFFFFFFF)
    state += [int.from_bytes(nonce[i : i + 4], "little") for i in range(0, 12, 4)]
    working = list(state)
    for _ in range(10):
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)
    out = bytearray()
    for i in range(16):
        out += ((working[i] + state[i]) & 0xFFFFFFFF).to_bytes(4, "little")
    return bytes(out)


def _chacha20_xor(key, counter, nonce, data):
    out = bytearray(len(data))
    for offset in range(0, len(data), 64):
        stream = _chacha20_block(key, counter + offset // 64, nonce)
        chunk = data[offset : offset + 64]
        for i, byte in enumerate(chunk):
            out[offset + i] = byte ^ stream[i]
    return bytes(out)


_POLY_P = (1 << 130) - 5


def _poly1305(key, message):
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:32], "little")
    acc = 0
    for offset in range(0, len(message), 16):
        block = message[offset : offset + 16]
        n = int.from_bytes(block + b"\x01", "little")
        acc = ((acc + n) * r) % _POLY_P
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _aead_mac_data(aad, ciphertext):
    def pad16(data):
        return b"\x00" * ((16 - len(data) % 16) % 16)

    return (
        aad
        + pad16(aad)
        + ciphertext
        + pad16(ciphertext)
        + len(aad).to_bytes(8, "little")
        + len(ciphertext).to_bytes(8, "little")
    )


def chacha20poly1305_encrypt(key, nonce, plaintext, aad=b""):
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("bad key or nonce length")
    otk = _chacha20_block(key, 0, nonce)[:32]
    ciphertext = _chacha20_xor(key, 1, nonce, plaintext)
    return ciphertext + _poly1305(otk, _aead_mac_data(aad, ciphertext))


def chacha20poly1305_decrypt(key, nonce, ciphertext, aad=b""):
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("bad key or nonce length")
    if len(ciphertext) < 16:
        raise ValueError("ciphertext too short")
    body, tag = ciphertext[:-16], ciphertext[-16:]
    otk = _chacha20_block(key, 0, nonce)[:32]
    expected = _poly1305(otk, _aead_mac_data(aad, body))
    if not _hmac.compare_digest(expected, tag):
        raise ValueError("authentication failed")
    return _chacha20_xor(key, 1, nonce, body)


# ---------- HKDF-SHA256 (RFC 5869) ----------
def hkdf_sha256(ikm, length=32, salt=None, info=b""):
    if length > 32 * 255:
        raise ValueError("length too large")
    prk = _hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = _hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]
