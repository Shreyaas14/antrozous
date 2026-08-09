"""Verification and decryption of stored messages (mcp_gate.open_envelope)."""

import json
import os
import tempfile
import unittest

import identity
import keys
import mcp_gate


class EnvelopeTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        # Recipient ("us") gets the real ANTROZOUS_HOME so unseal uses our key.
        os.environ["ANTROZOUS_HOME"] = os.path.join(self._tmp.name, "me")
        self.addCleanup(os.environ.pop, "ANTROZOUS_HOME", None)
        self.me = keys.load_or_create()
        self.me_pub = keys.public_bundle(self.me)
        self.me_id = identity.compose_agent_id("me", self.me_pub["fingerprint"])

        self.sender = keys.generate()
        self.sender_pub = keys.public_bundle(self.sender)
        self.sender_id = identity.compose_agent_id(
            "alice", self.sender_pub["fingerprint"]
        )
        self.ts = "2026-08-09T20:00:00"

    def build(
        self,
        content="hello",
        sender_record=None,
        sender_key_b64=None,
        from_agent=None,
        to_agent=None,
        timestamp=None,
        recipient_x=None,
    ):
        """Craft a v2 envelope, with every field overridable to forge attacks."""
        from_agent = from_agent or self.sender_id
        to_agent = to_agent or self.me_id
        timestamp = timestamp or self.ts
        inner = json.dumps(
            {
                "from_user": "alice",
                "to_user": "me",
                "content": content,
                "attachments": [],
            }
        ).encode()
        box = keys.seal(
            recipient_x or self.me_pub["x25519"],
            inner,
            aad=mcp_gate.seal_aad(from_agent, to_agent, timestamp),
        )
        payload = {
            "v": 2,
            "from_agent": from_agent,
            "to_agent": to_agent,
            "timestamp": timestamp,
            "ciphertext": box,
            "sender_ed25519": sender_key_b64 or self.sender_pub["ed25519"],
        }
        payload["signature"] = keys.sign(
            mcp_gate.signed_bytes(payload), sender_record or self.sender
        )
        return payload

    def assertRejected(self, message, needle):
        fields, note = mcp_gate.open_envelope(message)
        self.assertIsNone(fields, "content must not be exposed")
        self.assertIn(needle, note)


class HappyPathTests(EnvelopeTest):
    def test_valid_envelope_decrypts(self):
        fields, note = mcp_gate.open_envelope(self.build("the launch code is hunter2"))

        self.assertEqual(fields["content"], "the launch code is hunter2")
        self.assertEqual(fields["from_user"], "alice")
        self.assertIn("ENCRYPTED", note)
        self.assertIn("SIGNED", note)

    def test_v1_plaintext_passes_through_but_is_marked_unsigned(self):
        fields, note = mcp_gate.open_envelope(
            {
                "v": 1,
                "from_agent": "legacy",
                "from_user": "bob",
                "to_user": "me",
                "content": "plain text",
                "timestamp": self.ts,
            }
        )

        self.assertEqual(fields["content"], "plain text")
        self.assertIn("UNENCRYPTED", note)
        self.assertIn("UNSIGNED", note)

    def test_a_message_with_no_version_is_treated_as_v1(self):
        fields, note = mcp_gate.open_envelope(
            {"from_agent": "legacy", "content": "old", "timestamp": self.ts}
        )
        self.assertEqual(fields["content"], "old")
        self.assertIn("UNENCRYPTED", note)

    def test_attachment_refs_survive_the_seal(self):
        payload = self.build()
        inner = json.dumps(
            {
                "from_user": "alice",
                "to_user": "me",
                "content": "see attached",
                "attachments": [{"sha256": "ab" * 32, "mime": "image/png", "size": 12}],
            }
        ).encode()
        payload["ciphertext"] = keys.seal(
            self.me_pub["x25519"],
            inner,
            aad=mcp_gate.seal_aad(payload["from_agent"], payload["to_agent"], self.ts),
        )
        payload["signature"] = keys.sign(mcp_gate.signed_bytes(payload), self.sender)

        fields, _ = mcp_gate.open_envelope(payload)

        self.assertEqual(fields["attachments"][0]["mime"], "image/png")


class ImpersonationTests(EnvelopeTest):
    def test_a_valid_signature_from_the_wrong_key_is_rejected(self):
        # The core attack: an attacker seals and signs correctly, but claims someone
        # else's id. Their key does not hash to the fingerprint in that id.
        attacker = keys.generate()
        forged = self.build(
            sender_record=attacker,
            sender_key_b64=keys.public_bundle(attacker)["ed25519"],
            from_agent=self.sender_id,
        )

        self.assertRejected(forged, "IMPERSONATION REJECTED")

    def test_unqualified_sender_cannot_be_attributed(self):
        forged = self.build(from_agent="alice")
        self.assertRejected(forged, "no fingerprint")

    def test_unreadable_sender_key_is_rejected(self):
        self.assertRejected(self.build(sender_key_b64="not base64!!"), "unreadable")

    def test_missing_sender_key_is_rejected(self):
        payload = self.build()
        payload["sender_ed25519"] = ""
        self.assertRejected(payload, "unreadable")


class TamperingTests(EnvelopeTest):
    def test_altered_ciphertext_fails_the_signature(self):
        payload = self.build()
        payload["ciphertext"] = keys.seal(self.me_pub["x25519"], b"different")
        self.assertRejected(payload, "signature does not verify")

    def test_altered_timestamp_fails_the_signature(self):
        payload = self.build()
        payload["timestamp"] = "2026-01-01T00:00:00"
        self.assertRejected(payload, "signature does not verify")

    def test_rerouting_to_another_recipient_fails(self):
        # to_agent is signed, so a relay cannot redirect the envelope.
        payload = self.build()
        payload["to_agent"] = "someone.aaaaaaaa"
        self.assertRejected(payload, "signature does not verify")

    def test_missing_signature_is_rejected(self):
        payload = self.build()
        payload.pop("signature")
        self.assertRejected(payload, "signature does not verify")

    def test_box_sealed_to_someone_else_cannot_be_opened(self):
        other = keys.public_bundle(keys.generate())
        payload = self.build(recipient_x=other["x25519"])
        self.assertRejected(payload, "could not decrypt")

    def test_aad_mismatch_is_caught(self):
        # A correctly signed envelope whose AAD was built for a different pairing.
        payload = self.build()
        inner = json.dumps({"content": "x", "attachments": []}).encode()
        payload["ciphertext"] = keys.seal(
            self.me_pub["x25519"], inner, aad=b"wrong|pairing|now"
        )
        payload["signature"] = keys.sign(mcp_gate.signed_bytes(payload), self.sender)
        self.assertRejected(payload, "could not decrypt")

    def test_non_json_plaintext_is_rejected(self):
        payload = self.build()
        payload["ciphertext"] = keys.seal(
            self.me_pub["x25519"],
            b"not json at all",
            aad=mcp_gate.seal_aad(payload["from_agent"], payload["to_agent"], self.ts),
        )
        payload["signature"] = keys.sign(mcp_gate.signed_bytes(payload), self.sender)
        self.assertRejected(payload, "could not decrypt")

    def test_json_scalar_payload_is_rejected(self):
        payload = self.build()
        payload["ciphertext"] = keys.seal(
            self.me_pub["x25519"],
            b'"just a string"',
            aad=mcp_gate.seal_aad(payload["from_agent"], payload["to_agent"], self.ts),
        )
        payload["signature"] = keys.sign(mcp_gate.signed_bytes(payload), self.sender)
        self.assertRejected(payload, "not an object")


class SignedBytesTests(EnvelopeTest):
    def test_covers_every_routing_field(self):
        base = self.build()
        original = mcp_gate.signed_bytes(base)
        for field, value in (
            ("from_agent", "other.aaaaaaaa"),
            ("to_agent", "other.bbbbbbbb"),
            ("timestamp", "2020-01-01T00:00:00"),
            ("ciphertext", "AAAA"),
            ("v", 3),
        ):
            self.assertNotEqual(
                mcp_gate.signed_bytes(dict(base, **{field: value})),
                original,
                "%s must be covered by the signature" % field,
            )

    def test_is_deterministic_regardless_of_key_order(self):
        payload = self.build()
        reordered = {k: payload[k] for k in reversed(list(payload))}
        self.assertEqual(
            mcp_gate.signed_bytes(payload), mcp_gate.signed_bytes(reordered)
        )


if __name__ == "__main__":
    unittest.main()
