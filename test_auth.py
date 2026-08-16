"""Relay authorization: knowing an agent id must buy nothing.

Every test here is written from the attacker's seat — it knows the victim's full
agent id and nothing else, which is exactly the position anyone reading /health used
to be in.
"""

import base64
import os
import time
import unittest

from fastapi.testclient import TestClient

from cryptography.hazmat.primitives import serialization as _ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.antrozous import server


def _keypair():
    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(
        encoding=_ser.Encoding.Raw, format=_ser.PublicFormat.Raw
    )
    return priv, raw, base64.b64encode(raw).decode()


def _sign(priv, pub_b64, agent_id, method, path, ts=None, nonce=None):
    ts = ts if ts is not None else "%d" % int(time.time())
    nonce = nonce or base64.b16encode(os.urandom(12)).decode().lower()
    sig = base64.b64encode(
        priv.sign(server.auth_bytes(method, path, agent_id, ts, nonce))
    ).decode()
    return "%s %s:%s:%s:%s:%s" % (
        server.AUTH_SCHEME,
        agent_id,
        ts,
        nonce,
        pub_b64,
        sig,
    )


class AuthTest(unittest.TestCase):
    def setUp(self):
        server.inboxes.clear()
        server.agent_keys.clear()
        server._seen_nonces.clear()
        server._tickets.clear()
        self.client = TestClient(server.app)

        self.priv, self.raw, self.pub = _keypair()
        self.fp = server._fingerprint(self.raw)
        self.agent = "victim.%s" % self.fp
        server.inboxes[self.agent] = [{"from_agent": "someone", "content": "secret"}]

    def auth(self, method, path, agent_id=None, **kw):
        return _sign(self.priv, self.pub, agent_id or self.agent, method, path, **kw)

    # ---------- the whole point ----------
    def test_read_without_signature_is_rejected(self):
        r = self.client.get("/inbox/%s" % self.agent)
        self.assertEqual(r.status_code, 401)

    def test_consume_without_signature_is_rejected(self):
        r = self.client.post("/inbox/%s/consume?count=-1" % self.agent)
        self.assertEqual(r.status_code, 401)
        self.assertEqual(len(server.inboxes[self.agent]), 1, "mail must survive")

    def test_read_with_signature_succeeds(self):
        path = "/inbox/%s" % self.agent
        r = self.client.get(path, headers={"authorization": self.auth("GET", path)})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.json()), 1)

    def test_another_key_cannot_read_the_same_id(self):
        """The attacker knows the id exactly, and holds a perfectly good key."""
        other_priv, _, other_pub = _keypair()
        path = "/inbox/%s" % self.agent
        header = _sign(other_priv, other_pub, self.agent, "GET", path)
        r = self.client.get(path, headers={"authorization": header})
        self.assertEqual(r.status_code, 401)

    # ---------- replay / tamper ----------
    def test_nonce_cannot_be_replayed(self):
        path = "/inbox/%s" % self.agent
        header = self.auth("GET", path)
        self.assertEqual(
            self.client.get(path, headers={"authorization": header}).status_code, 200
        )
        self.assertEqual(
            self.client.get(path, headers={"authorization": header}).status_code, 401
        )

    def test_stale_timestamp_is_rejected(self):
        path = "/inbox/%s" % self.agent
        old = "%d" % (int(time.time()) - server.MAX_CLOCK_SKEW - 5)
        r = self.client.get(
            path, headers={"authorization": self.auth("GET", path, ts=old)}
        )
        self.assertEqual(r.status_code, 401)

    def test_query_string_is_covered_by_the_signature(self):
        """Signed for count=1, sent as count=99 — the extra deletion must not land."""
        signed_path = "/inbox/%s/consume?count=1" % self.agent
        header = self.auth("POST", signed_path)
        r = self.client.post(
            "/inbox/%s/consume?count=99" % self.agent,
            headers={"authorization": header},
        )
        self.assertEqual(r.status_code, 401)

    def test_method_is_covered_by_the_signature(self):
        path = "/inbox/%s" % self.agent
        r = self.client.get(path, headers={"authorization": self.auth("POST", path)})
        self.assertEqual(r.status_code, 401)

    # ---------- sending ----------
    def test_cannot_send_as_someone_else(self):
        body = {
            "v": 1,
            "from_agent": self.agent,
            "to_agent": "bob.aaaaaaaa",
            "timestamp": "2026-01-01T00:00:00",
            "content": "forged",
        }
        other_priv, _, other_pub = _keypair()
        header = _sign(other_priv, other_pub, self.agent, "POST", "/send")
        r = self.client.post("/send", json=body, headers={"authorization": header})
        self.assertEqual(r.status_code, 401)

    def test_can_send_as_self(self):
        body = {
            "v": 1,
            "from_agent": self.agent,
            "to_agent": "bob.aaaaaaaa",
            "timestamp": "2026-01-01T00:00:00",
            "content": "hi",
        }
        header = self.auth("POST", "/send")
        r = self.client.post("/send", json=body, headers={"authorization": header})
        self.assertEqual(r.status_code, 200)

    # ---------- metadata ----------
    def test_health_is_not_a_directory(self):
        r = self.client.get("/health").json()
        self.assertEqual(r["agents"], 1, "count only, never the ids")
        self.assertNotIn("ws_connections", r)

    def test_failures_are_indistinguishable(self):
        """A wrong signature and a nonexistent inbox must look identical."""
        real = self.client.get("/inbox/%s" % self.agent)
        missing = self.client.get("/inbox/ghost.%s" % self.fp)
        self.assertEqual(real.status_code, missing.status_code)
        self.assertEqual(real.json(), missing.json())

    # ---------- websocket ----------
    def test_ws_without_ticket_is_closed(self):
        with self.assertRaises(Exception):
            with self.client.websocket_connect("/ws/%s" % self.agent) as ws:
                ws.receive_text()

    def test_ws_with_ticket_connects(self):
        path = "/auth/ticket?agent_id=%s" % self.agent
        r = self.client.post(path, headers={"authorization": self.auth("POST", path)})
        self.assertEqual(r.status_code, 200)
        ticket = r.json()["ticket"]
        with self.client.websocket_connect(
            "/ws/%s?ticket=%s" % (self.agent, ticket)
        ) as ws:
            self.assertEqual(ws.receive_json()["type"], "connected")

    def test_ticket_is_bound_to_one_agent(self):
        path = "/auth/ticket?agent_id=%s" % self.agent
        ticket = self.client.post(
            path, headers={"authorization": self.auth("POST", path)}
        ).json()["ticket"]
        with self.assertRaises(Exception):
            with self.client.websocket_connect(
                "/ws/other.%s?ticket=%s" % (self.fp, ticket)
            ) as ws:
                ws.receive_text()


class KeyRegistryTest(unittest.TestCase):
    def setUp(self):
        server.agent_keys.clear()
        server.inboxes.clear()
        self.client = TestClient(server.app)
        self.priv, self.raw, self.pub = _keypair()
        self.fp = server._fingerprint(self.raw)
        self.x = base64.b64encode(os.urandom(32)).decode()

    def publish(self, name, pub=None, x=None, signature=None):
        body = {"ed25519": pub or self.pub, "x25519": x or self.x}
        if signature:
            body["signature"] = signature
        return self.client.post("/keys/%s.%s" % (name, self.fp), json=body)

    def test_any_session_name_resolves_the_same_bundle(self):
        """The bug that silently downgraded sends to plaintext."""
        self.assertEqual(self.publish("anish-bot-1").status_code, 200)
        r = self.client.get("/keys/anish-bot.%s" % self.fp)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["x25519"], self.x)

    def test_a_foreign_key_cannot_claim_a_fingerprint(self):
        """A key that does not hash to the address is refused outright."""
        _, _, attacker_pub = _keypair()
        self.assertEqual(self.publish("victim", pub=attacker_pub).status_code, 400)

    def test_a_ground_collision_cannot_steal_the_address(self):
        """Stand in for a 40-bit grind: pretend the attacker registered first.

        A real collision cannot be produced in a unit test, so the incumbent is
        seeded directly — what matters is that a SECOND identity key for one
        fingerprint is refused rather than silently overwriting.
        """
        _, _, incumbent_pub = _keypair()
        server.agent_keys[self.fp] = {
            "ed25519": incumbent_pub,
            "x25519": self.x,
            "first_seen": "2026-01-01T00:00:00",
        }
        r = self.publish("victim")
        self.assertEqual(r.status_code, 409)
        self.assertEqual(server.agent_keys[self.fp]["ed25519"], incumbent_pub)

    def test_rotation_needs_a_signature_from_the_registered_key(self):
        self.publish("victim")
        new_x = base64.b64encode(os.urandom(32)).decode()
        self.assertEqual(self.publish("victim", x=new_x).status_code, 403)

        sig = base64.b64encode(
            self.priv.sign(server.keyreg_bytes(self.fp, self.pub, new_x))
        ).decode()
        r = self.publish("victim", x=new_x, signature=sig)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["rotated"])
        self.assertEqual(server.agent_keys[self.fp]["x25519"], new_x)

    def test_republishing_the_same_bundle_is_idempotent(self):
        self.publish("victim")
        r = self.publish("victim")
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.json()["rotated"])


class MessageLimitsTest(unittest.TestCase):
    """Message bodies were uncapped, which matters once diffs travel inline."""

    def setUp(self):
        server.inboxes.clear()
        server.agent_keys.clear()
        server._seen_nonces.clear()
        self.client = TestClient(server.app)
        self.priv, self.raw, self.pub = _keypair()
        self.fp = server._fingerprint(self.raw)
        self.agent = "sender.%s" % self.fp

    def send(self, content):
        header = _sign(self.priv, self.pub, self.agent, "POST", "/send")
        return self.client.post(
            "/send",
            json={
                "v": 1,
                "from_agent": self.agent,
                "to_agent": "bob.aaaaaaaa",
                "timestamp": "2026-01-01T00:00:00",
                "content": content,
            },
            headers={"authorization": header},
        )

    def test_an_ordinary_message_is_fine(self):
        self.assertEqual(self.send("a patch, say").status_code, 200)

    def test_an_oversized_body_is_refused(self):
        r = self.send("x" * (server.MAX_MESSAGE_BYTES + 1))
        self.assertEqual(r.status_code, 413)
        self.assertEqual(server.inboxes.get("bob.aaaaaaaa", []), [])

    def test_a_full_queue_refuses_rather_than_evicting(self):
        """Evicting would let a sender push unread messages out of your queue."""
        server.inboxes["bob.aaaaaaaa"] = [
            {"n": i} for i in range(server.MAX_INBOX_MESSAGES)
        ]
        r = self.send("one more")
        self.assertEqual(r.status_code, 507)
        self.assertEqual(len(server.inboxes["bob.aaaaaaaa"]), server.MAX_INBOX_MESSAGES)
        self.assertEqual(server.inboxes["bob.aaaaaaaa"][0], {"n": 0}, "oldest kept")


class InboxListingTest(unittest.TestCase):
    """Renaming or closing a tab must not strand mail."""

    def setUp(self):
        server.inboxes.clear()
        server.agent_keys.clear()
        server._seen_nonces.clear()
        self.client = TestClient(server.app)
        self.priv, self.raw, self.pub = _keypair()
        self.fp = server._fingerprint(self.raw)
        self.agent = "ssh-reyaas.%s" % self.fp
        # One current inbox, one left behind by a rename, one stranger's.
        server.inboxes[self.agent] = [{"content": "new"}]
        server.inboxes["agent-shreyaas.%s" % self.fp] = [{"c": 1}, {"c": 2}]
        server.inboxes["someone-else.aaaaaaaa"] = [{"c": 3}]

    def list(self, agent_id=None):
        agent_id = agent_id or self.agent
        path = "/inboxes?agent_id=%s" % agent_id
        header = _sign(self.priv, self.pub, agent_id, "GET", path)
        return self.client.get(path, headers={"authorization": header})

    def test_lists_every_inbox_for_my_fingerprint(self):
        body = self.list().json()
        found = {i["agent_id"]: i["pending"] for i in body["inboxes"]}
        self.assertEqual(found, {self.agent: 1, "agent-shreyaas.%s" % self.fp: 2})

    def test_never_lists_someone_elses(self):
        listed = [i["agent_id"] for i in self.list().json()["inboxes"]]
        self.assertNotIn("someone-else.aaaaaaaa", listed)

    def test_requires_a_signature(self):
        r = self.client.get("/inboxes?agent_id=%s" % self.agent)
        self.assertEqual(r.status_code, 401)

    def test_cannot_list_another_fingerprints_inboxes(self):
        """Signing as yourself must not let you enumerate a different device."""
        r = self.list(agent_id="someone-else.aaaaaaaa")
        self.assertEqual(r.status_code, 401)


class AliasTest(unittest.TestCase):
    """Bare names: convenient to hand out, never trusted on their own."""

    def setUp(self):
        server.agent_keys.clear()
        server.aliases.clear()
        server.inboxes.clear()
        self.client = TestClient(server.app)
        self.priv, self.raw, self.pub = _keypair()
        self.fp = server._fingerprint(self.raw)
        self.x = base64.b64encode(os.urandom(32)).decode()

    def publish(self, name, pub=None, fp=None):
        return self.client.post(
            "/keys/%s.%s" % (name, fp or self.fp),
            json={"ed25519": pub or self.pub, "x25519": self.x},
        )

    def test_name_resolves_to_the_fingerprint_that_claimed_it(self):
        self.assertEqual(
            self.publish("agent-shreyaas").json()["alias"], "agent-shreyaas"
        )
        r = self.client.get("/resolve/agent-shreyaas")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["agent_id"], "agent-shreyaas.%s" % self.fp)

    def test_unclaimed_name_is_a_404(self):
        self.assertEqual(self.client.get("/resolve/nobody").status_code, 404)

    def test_first_claim_wins(self):
        self.publish("agent-shreyaas")
        other_priv, other_raw, other_pub = _keypair()
        other_fp = server._fingerprint(other_raw)
        r = self.publish("agent-shreyaas", pub=other_pub, fp=other_fp)
        # The squatter still owns its own qualified id, it just gets no short name.
        self.assertEqual(r.status_code, 200)
        self.assertIsNone(r.json()["alias"])
        self.assertEqual(
            self.client.get("/resolve/agent-shreyaas").json()["fingerprint"], self.fp
        )

    def test_alias_never_grants_access(self):
        """Resolving a name tells you WHO to talk to, never lets you act as them."""
        self.publish("agent-shreyaas")
        server.inboxes["agent-shreyaas.%s" % self.fp] = [{"content": "secret"}]
        r = self.client.get("/inbox/agent-shreyaas")
        self.assertEqual(r.status_code, 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)
