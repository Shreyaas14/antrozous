import base64
import os
import tempfile
import unittest

import identity
import keys


class KeyTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        os.environ["ANTROZOUS_HOME"] = os.path.join(self._tmp.name, "home")
        self.addCleanup(self._tmp.cleanup)
        self.addCleanup(os.environ.pop, "ANTROZOUS_HOME", None)


class FingerprintTests(KeyTest):
    def test_fingerprint_is_a_legal_id_component(self):
        fp = keys.public_bundle(keys.generate())["fingerprint"]

        self.assertEqual(len(fp), keys.FINGERPRINT_CHARS)
        self.assertIsNotNone(identity.FINGERPRINT_RE.match(fp), fp)

    def test_fingerprint_is_deterministic(self):
        record = keys.generate()
        self.assertEqual(
            keys.public_bundle(record)["fingerprint"],
            keys.public_bundle(record)["fingerprint"],
        )

    def test_different_keys_give_different_fingerprints(self):
        # This is the property that stops two people who pick the same name from
        # sharing an inbox.
        seen = {keys.public_bundle(keys.generate())["fingerprint"] for _ in range(25)}
        self.assertEqual(len(seen), 25)

    def test_same_name_two_users_do_not_collide(self):
        a = keys.public_bundle(keys.generate())["fingerprint"]
        b = keys.public_bundle(keys.generate())["fingerprint"]

        self.assertNotEqual(
            identity.compose_agent_id("shreyaas", a),
            identity.compose_agent_id("shreyaas", b),
        )


class KeyStorageTests(KeyTest):
    def test_key_is_created_once_and_reused(self):
        first = keys.load_or_create()

        self.assertEqual(keys.load_or_create(), first)
        self.assertTrue(os.path.isfile(keys.key_path()))

    def test_key_file_is_not_world_readable(self):
        keys.load_or_create()
        self.assertEqual(os.stat(keys.key_path()).st_mode & 0o077, 0)

    def test_fingerprint_survives_a_reload(self):
        fp = keys.my_fingerprint()
        self.assertEqual(keys.my_fingerprint(), fp)

    def test_key_lives_under_the_overridable_home(self):
        self.assertTrue(keys.key_path().startswith(os.environ["ANTROZOUS_HOME"]))


class SignatureTests(KeyTest):
    def setUp(self):
        super().setUp()
        self.record = keys.load_or_create()
        self.pub = keys.public_bundle(self.record)

    def test_roundtrip(self):
        sig = keys.sign(b"payload", self.record)
        self.assertTrue(keys.verify(self.pub["ed25519"], sig, b"payload"))

    def test_tampered_payload_fails(self):
        sig = keys.sign(b"payload", self.record)
        self.assertFalse(keys.verify(self.pub["ed25519"], sig, b"payload!"))

    def test_wrong_key_fails(self):
        sig = keys.sign(b"payload", self.record)
        other = keys.public_bundle(keys.generate())
        self.assertFalse(keys.verify(other["ed25519"], sig, b"payload"))

    def test_garbage_signature_is_rejected_not_raised(self):
        for bad in ("", "not-base64!!", base64.b64encode(b"short").decode()):
            self.assertFalse(keys.verify(self.pub["ed25519"], bad, b"payload"))


class SealTests(KeyTest):
    def setUp(self):
        super().setUp()
        self.record = keys.load_or_create()
        self.pub = keys.public_bundle(self.record)

    def test_roundtrip(self):
        box = keys.seal(self.pub["x25519"], b"secret")
        self.assertEqual(keys.unseal(box, self.record), b"secret")

    def test_aad_must_match(self):
        box = keys.seal(self.pub["x25519"], b"secret", aad=b"a->b")

        self.assertEqual(keys.unseal(box, self.record, aad=b"a->b"), b"secret")
        with self.assertRaises(keys.CryptoError):
            keys.unseal(box, self.record, aad=b"a->c")

    def test_other_recipients_cannot_open_it(self):
        box = keys.seal(self.pub["x25519"], b"secret")
        with self.assertRaises(keys.CryptoError):
            keys.unseal(box, keys.generate())

    def test_ephemeral_keys_make_ciphertexts_unique(self):
        boxes = {keys.seal(self.pub["x25519"], b"same") for _ in range(10)}
        self.assertEqual(len(boxes), 10)

    def test_truncated_box_is_rejected(self):
        with self.assertRaises(keys.CryptoError):
            keys.unseal(base64.b64encode(b"\x01" + b"0" * 20).decode(), self.record)

    def test_unknown_version_is_rejected(self):
        with self.assertRaises(keys.CryptoError):
            keys.unseal(base64.b64encode(b"\x09" + b"0" * 80).decode(), self.record)

    def test_flipped_ciphertext_bit_is_rejected(self):
        raw = bytearray(base64.b64decode(keys.seal(self.pub["x25519"], b"secret")))
        raw[-1] ^= 0x01
        with self.assertRaises(keys.CryptoError):
            keys.unseal(base64.b64encode(bytes(raw)).decode(), self.record)


if __name__ == "__main__":
    unittest.main()
