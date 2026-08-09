"""RFC vectors for the vendored primitives, plus cross-backend compatibility.

The cross-backend tests are the ones that matter: a message sealed by a machine with
`cryptography` must open on a machine using the fallback, and vice versa.
"""

import os
import unittest

import _purecrypto as pc

try:
    from cryptography.hazmat.primitives import serialization
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

    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False


def _raw_pub(key):
    return key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )


class Ed25519VectorTests(unittest.TestCase):
    """RFC 8032 section 7.1."""

    VECTORS = [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555"
            "fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
            "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
    ]

    def test_public_key_derivation(self):
        for seed_hex, pub_hex, _, _ in self.VECTORS:
            self.assertEqual(
                pc.ed25519_public_from_seed(bytes.fromhex(seed_hex)).hex(), pub_hex
            )

    def test_signatures_match_the_rfc(self):
        for seed_hex, _, msg_hex, sig_hex in self.VECTORS:
            self.assertEqual(
                pc.ed25519_sign(bytes.fromhex(seed_hex), bytes.fromhex(msg_hex)).hex(),
                sig_hex,
            )

    def test_verifies_the_rfc_signatures(self):
        for _, pub_hex, msg_hex, sig_hex in self.VECTORS:
            self.assertTrue(
                pc.ed25519_verify(
                    bytes.fromhex(pub_hex),
                    bytes.fromhex(sig_hex),
                    bytes.fromhex(msg_hex),
                )
            )

    def test_rejects_tampering(self):
        seed_hex, pub_hex, msg_hex, sig_hex = self.VECTORS[1]
        pub, sig = bytes.fromhex(pub_hex), bytearray(bytes.fromhex(sig_hex))
        self.assertFalse(pc.ed25519_verify(pub, bytes(sig), b"\x73"))
        sig[0] ^= 0x01
        self.assertFalse(pc.ed25519_verify(pub, bytes(sig), bytes.fromhex(msg_hex)))

    def test_rejects_oversized_s(self):
        # S >= L must be refused, or signatures become malleable.
        _, pub_hex, msg_hex, sig_hex = self.VECTORS[1]
        sig = bytes.fromhex(sig_hex)
        s = int.from_bytes(sig[32:], "little") + pc.L
        forged = sig[:32] + s.to_bytes(32, "little")
        self.assertFalse(
            pc.ed25519_verify(bytes.fromhex(pub_hex), forged, bytes.fromhex(msg_hex))
        )

    def test_rejects_malformed_inputs(self):
        self.assertFalse(pc.ed25519_verify(b"\x00" * 32, b"\x00" * 64, b"m"))
        self.assertFalse(pc.ed25519_verify(b"\x00" * 31, b"\x00" * 64, b"m"))
        self.assertFalse(pc.ed25519_verify(b"\x00" * 32, b"\x00" * 63, b"m"))


class X25519VectorTests(unittest.TestCase):
    """RFC 7748 section 6.1."""

    A_PRIV = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    A_PUB = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    B_PRIV = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
    B_PUB = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    SHARED = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

    def test_public_keys(self):
        self.assertEqual(
            pc.x25519_public_from_scalar(bytes.fromhex(self.A_PRIV)).hex(), self.A_PUB
        )
        self.assertEqual(
            pc.x25519_public_from_scalar(bytes.fromhex(self.B_PRIV)).hex(), self.B_PUB
        )

    def test_shared_secret_both_directions(self):
        self.assertEqual(
            pc.x25519(bytes.fromhex(self.A_PRIV), bytes.fromhex(self.B_PUB)).hex(),
            self.SHARED,
        )
        self.assertEqual(
            pc.x25519(bytes.fromhex(self.B_PRIV), bytes.fromhex(self.A_PUB)).hex(),
            self.SHARED,
        )


class ChaChaPolyVectorTests(unittest.TestCase):
    """RFC 8439 section 2.8.2."""

    KEY = bytes(range(0x80, 0xA0))
    NONCE = bytes.fromhex("070000004041424344454647")
    AAD = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    PLAINTEXT = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you "
        b"only one tip for the future, sunscreen would be it."
    )
    CIPHERTEXT = bytes.fromhex(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b6116"
    )
    TAG = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")

    def test_encrypt_matches_the_rfc(self):
        out = pc.chacha20poly1305_encrypt(
            self.KEY, self.NONCE, self.PLAINTEXT, self.AAD
        )
        self.assertEqual(out[:-16], self.CIPHERTEXT)
        self.assertEqual(out[-16:], self.TAG)

    def test_decrypt_roundtrip(self):
        self.assertEqual(
            pc.chacha20poly1305_decrypt(
                self.KEY, self.NONCE, self.CIPHERTEXT + self.TAG, self.AAD
            ),
            self.PLAINTEXT,
        )

    def test_bad_tag_is_rejected(self):
        tag = bytearray(self.TAG)
        tag[0] ^= 0x01
        with self.assertRaises(ValueError):
            pc.chacha20poly1305_decrypt(
                self.KEY, self.NONCE, self.CIPHERTEXT + bytes(tag), self.AAD
            )

    def test_wrong_aad_is_rejected(self):
        with self.assertRaises(ValueError):
            pc.chacha20poly1305_decrypt(
                self.KEY, self.NONCE, self.CIPHERTEXT + self.TAG, b"other"
            )

    def test_empty_plaintext_roundtrips(self):
        out = pc.chacha20poly1305_encrypt(self.KEY, self.NONCE, b"", b"")
        self.assertEqual(
            pc.chacha20poly1305_decrypt(self.KEY, self.NONCE, out, b""), b""
        )

    def test_multiblock_plaintext(self):
        data = os.urandom(1000)
        out = pc.chacha20poly1305_encrypt(self.KEY, self.NONCE, data, b"aad")
        self.assertEqual(
            pc.chacha20poly1305_decrypt(self.KEY, self.NONCE, out, b"aad"), data
        )


@unittest.skipUnless(HAVE_CRYPTOGRAPHY, "cryptography not installed")
class CrossBackendTests(unittest.TestCase):
    """Wire compatibility: either backend must accept the other's output."""

    def test_ed25519_public_keys_agree(self):
        seed = os.urandom(32)
        theirs = _raw_pub(Ed25519PrivateKey.from_private_bytes(seed).public_key())
        self.assertEqual(pc.ed25519_public_from_seed(seed), theirs)

    def test_pure_signature_verifies_under_cryptography(self):
        seed, msg = os.urandom(32), b"cross-backend payload"
        sig = pc.ed25519_sign(seed, msg)
        pub = Ed25519PrivateKey.from_private_bytes(seed).public_key()
        pub.verify(sig, msg)  # raises on failure

    def test_cryptography_signature_verifies_under_pure(self):
        seed, msg = os.urandom(32), b"cross-backend payload"
        sig = Ed25519PrivateKey.from_private_bytes(seed).sign(msg)
        self.assertTrue(pc.ed25519_verify(pc.ed25519_public_from_seed(seed), sig, msg))

    def test_x25519_public_keys_agree(self):
        scalar = os.urandom(32)
        theirs = _raw_pub(X25519PrivateKey.from_private_bytes(scalar).public_key())
        self.assertEqual(pc.x25519_public_from_scalar(scalar), theirs)

    def test_x25519_exchange_agrees(self):
        a, b = os.urandom(32), os.urandom(32)
        b_pub = pc.x25519_public_from_scalar(b)

        theirs = X25519PrivateKey.from_private_bytes(a).exchange(
            X25519PublicKey.from_public_bytes(b_pub)
        )
        self.assertEqual(pc.x25519(a, b_pub), theirs)

    def test_aead_interoperates_both_directions(self):
        key, nonce, pt, aad = os.urandom(32), os.urandom(12), b"secret", b"bind"

        pure_ct = pc.chacha20poly1305_encrypt(key, nonce, pt, aad)
        self.assertEqual(ChaCha20Poly1305(key).decrypt(nonce, pure_ct, aad), pt)

        lib_ct = ChaCha20Poly1305(key).encrypt(nonce, pt, aad)
        self.assertEqual(pc.chacha20poly1305_decrypt(key, nonce, lib_ct, aad), pt)

    def test_hkdf_agrees(self):
        ikm, info = os.urandom(64), b"antrozous-seal-v1"
        theirs = HKDF(algorithm=SHA256(), length=32, salt=None, info=info).derive(ikm)
        self.assertEqual(pc.hkdf_sha256(ikm, 32, None, info), theirs)


if __name__ == "__main__":
    unittest.main()
