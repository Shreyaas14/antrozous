"""The startup prompt has to actually rename you.

The bug this covers: the popup asks for a name every launch, but only wrote the
SAVED default on first setup. Sends, key publishing and the alias all derive from
the account address, so after that first time a rename silently applied to nothing
you could see — you'd tell people "I'm anish-bot" while every message you sent said
anish-bot-1.
"""

import contextlib
import json
import os
import shutil
import tempfile
import threading
import time
import unittest

import identity


@contextlib.contextmanager
def _env(**overrides):
    """Set/clear env vars for the duration of a block. A value of None unsets."""
    saved = {k: os.environ.get(k) for k in overrides}
    try:
        for k, v in overrides.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


@contextlib.contextmanager
def mock_primary(value):
    """Patch identity.is_primary, which is what inbox_addresses consults."""
    import identity as _identity

    real = _identity.is_primary
    _identity.is_primary = lambda: value
    try:
        yield
    finally:
        _identity.is_primary = real


class SessionRenameTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        os.environ["ANTROZOUS_HOME"] = self.home
        os.environ.pop("AGENT_ID", None)
        os.environ["ANTROZOUS_STARTUP_PROMPT"] = "0"

        import identity
        import mcp_gate

        self.identity = identity
        self.gate = mcp_gate

        self.base = tempfile.mkdtemp()
        # The gate publishes keys after a rename; that is network and not under test.
        # Kept so the one test that IS about publishing can call the real thing.
        self.real_publish_identities = mcp_gate._publish_identities
        self.gate._publish_identities = lambda: True
        self.gate.SESSION_AGENT_ID = None
        self.gate._startup_fingerprint = "kbjz3w4a"
        self.identity.find_directory = lambda: self.base

    def tearDown(self):
        # Put the module back, or the next setUp captures THIS test's stub as the
        # "real" function and every later test silently exercises a lambda.
        self.gate._publish_identities = self.real_publish_identities
        shutil.rmtree(self.home, ignore_errors=True)
        shutil.rmtree(self.base, ignore_errors=True)
        os.environ.pop("ANTROZOUS_HOME", None)

    def reply(self, typed, suggested, peers=None):
        """Drive the startup prompt's answer as if the user typed `typed`."""
        self.gate._startup_pending = True
        self.gate._startup_suggested = suggested
        self.identity.live_sessions = lambda: dict(peers or {})
        handled = self.gate._handle_startup_reply(
            {
                "id": self.gate.STARTUP_RID,
                "result": {"action": "accept", "content": {"name": typed}},
            }
        )
        self.assertTrue(handled)

    def saved(self):
        return self.identity.resolve_agent_id(self.base)

    def test_first_choice_is_saved(self):
        self.reply("anish-bot-1", suggested="agent-shreyaas")
        self.assertEqual(self.saved(), "anish-bot-1.kbjz3w4a")

    def test_the_prompt_says_which_one_it_is(self):
        """The wording has to match the behaviour, or people rename nothing."""
        prompt, schema = self.gate._session_prompt("agent-shreyaas", "kbjz3w4a", {})
        self.assertIn("FIRST run", prompt)
        self.assertIn("YOUR ADDRESS", prompt)
        # The old two-branch copy is gone: this popup never names a tab, only
        # the account, so nothing here should still call it "this session's id".
        self.assertNotIn("THIS SESSION'S", prompt)
        self.assertNotIn("This session:", prompt)
        self.assertIn("account", schema["properties"]["name"]["title"].lower())
        # Declining must not promise a fallback id — it adopts nothing at all.
        self.assertIn("no address", prompt.lower())

    def test_set_identity_publishes_under_the_new_name(self):
        """A rename has to claim the new alias, not wait for the next check_inbox.

        Otherwise you tell someone "I'm agent-anish" and sends to that bare name
        fail to resolve until you happen to poll your inbox.
        """
        self.reply("anish-bot-1", suggested="agent-shreyaas")
        published = []
        self.gate._publish_identities = lambda: published.append(
            self.gate.account_agent_id()
        )
        # Renames require the user's approval in a popup; stand in for the tap.
        self.gate.CLIENT_ELICITATION = True
        self.gate._elicit = lambda prompt, schema: ("accept", {})
        self.gate.tool_result = lambda *a, **kw: None
        self.gate.do_set_identity(1, {"agent_id": "agent-anish.kbjz3w4a"})

        self.assertEqual(self.saved(), "agent-anish.kbjz3w4a")
        self.assertEqual(published, ["agent-anish.kbjz3w4a"])

    def test_publishing_retries_after_the_relay_loses_state(self):
        """The relay stores keys in memory, so a redeploy drops them all.

        A gate that published once and remembered it would never notice, and every
        message to it would silently downgrade to plaintext.
        """
        published = []
        self.gate.publish_keys = lambda addr: published.append(addr) or True
        self.gate._published.clear()

        # One publish per unique address per call — account and session may or may
        # not be the same id, depending on the subclass's fixture.
        per_call = len({self.gate.account_agent_id(), self.gate.current_agent_id()})
        self.real_publish_identities()
        self.real_publish_identities()
        self.assertEqual(len(published), 2 * per_call, "must republish, not skip")

    def test_whoami_flags_the_mismatch(self):
        self.reply("anish-bot", suggested="agent-shreyaas")
        self.identity.mark_confirmed(self.base)
        self.reply(
            "scratch", suggested="anish-bot-2", peers={99999: "anish-bot.kbjz3w4a"}
        )

        captured = {}
        self.gate.tool_result = lambda _id, text, **kw: captured.update(text=text)
        self.gate._ws_url = lambda a: "wss://test/ws/" + a
        self.gate.do_whoami(1, {})
        self.assertIn("scratch.kbjz3w4a", captured["text"])
        self.assertIn("anish-bot.kbjz3w4a", captured["text"])
        self.assertIn("sends as", captured["text"])


class SessionAdoptionTests(SessionRenameTest):
    def test_first_run_still_prompts(self):
        """A fresh install has no account name, so the popup must appear."""
        self.assertTrue(self.gate.needs_account_setup())

    def test_later_runs_do_not_prompt(self):
        identity.set_agent_id(self.home, "anish-bot.e5ox72jb")
        identity.mark_confirmed(self.home)
        self.assertFalse(self.gate.needs_account_setup())

    def test_new_session_takes_the_next_ordinal(self):
        identity.save_fingerprint("e5ox72jb")
        identity.set_agent_id(self.home, "anish-bot.e5ox72jb")
        with _env(CLAUDE_CODE_SESSION_ID="sess-a"):
            first = self.gate.resume_or_assign_session_id()
        with _env(CLAUDE_CODE_SESSION_ID="sess-b"):
            second = self.gate.resume_or_assign_session_id()
        self.assertEqual(first, "anish-bot-1.e5ox72jb")
        self.assertEqual(second, "anish-bot-2.e5ox72jb")

    def test_resumed_session_keeps_its_id(self):
        identity.save_fingerprint("e5ox72jb")
        identity.set_agent_id(self.home, "anish-bot.e5ox72jb")
        with _env(CLAUDE_CODE_SESSION_ID="sess-a"):
            first = self.gate.resume_or_assign_session_id()
            identity.unregister_session()
            again = self.gate.resume_or_assign_session_id()
        self.assertEqual(first, again)

    def test_a_resumed_session_does_not_burn_an_ordinal(self):
        identity.save_fingerprint("e5ox72jb")
        identity.set_agent_id(self.home, "anish-bot.e5ox72jb")
        with _env(CLAUDE_CODE_SESSION_ID="sess-a"):
            self.gate.resume_or_assign_session_id()
            self.gate.resume_or_assign_session_id()
        self.assertEqual(
            identity._read_json(identity._global_path())["session_counter"], 1
        )

    def test_accepting_the_first_run_prompt_derives_this_session_id(self):
        """The task's headline behaviour: accepting names the account, and this
        tab's own address comes out numbered, not equal to the bare account."""
        identity.save_fingerprint("kbjz3w4a")
        # Stand in for real key generation. Restored on cleanup -- leaving the
        # real ensure_keys() replaced would stop every later test in this run
        # from caching a real fingerprint for ITS OWN home directory.
        self.addCleanup(setattr, self.gate, "ensure_keys", self.gate.ensure_keys)
        self.gate.ensure_keys = lambda: "kbjz3w4a"
        self.reply("anish-bot", suggested="agent-shreyaas")
        self.assertEqual(self.saved(), "anish-bot.kbjz3w4a")
        self.assertEqual(self.gate.SESSION_AGENT_ID, "anish-bot-1.kbjz3w4a")

    def test_accept_writes_the_account_name_through_the_locked_helper(self):
        """The gate must not reach into identity's private read/write helpers --
        set_account_name is what takes the lock protecting session_counter."""
        calls = []
        # Restored on cleanup -- identity is a shared module, and every other
        # test needs the REAL set_account_name to persist to disk.
        self.addCleanup(
            setattr, self.identity, "set_account_name", self.identity.set_account_name
        )
        self.identity.set_account_name = lambda name: calls.append(name) or name
        self.reply("anish-bot", suggested="agent-shreyaas")
        self.assertEqual(calls, ["anish-bot"])

    def test_env_pinned_session_does_not_derive_or_register(self):
        """current_agent_id() checks $AGENT_ID first, so that is already this
        session's address. Deriving and registering a different one would
        advertise an address the session never actually answers on.

        An account must already exist for this to actually exercise the bug:
        resume_or_assign_session_id() is a no-op without one regardless of
        $AGENT_ID, which is what let an earlier, weaker version of this test
        pass against the unfixed code too.
        """
        identity.save_fingerprint("e5ox72jb")
        identity.set_agent_id(self.home, "anish-bot.e5ox72jb")
        identity.mark_confirmed(self.home)
        with _env(AGENT_ID="pinned.e5ox72jb"):
            self.gate.schedule_identity_setup()
        self.assertEqual(identity.session_records(), {})
        self.assertIsNone(self.gate.SESSION_AGENT_ID)

    def test_the_no_prompt_path_does_not_block_on_publishing(self):
        """This branch runs on the main read loop on every later launch; a
        stalled relay must not delay MCP initialization by a publish call.

        Asserts on wall-clock time, not just eventual side effects: a version
        that calls _publish_identities() inline still sets SESSION_AGENT_ID and
        eventually calls it, just after `finish` times itself out -- so those
        two facts alone don't prove the call didn't block.
        """
        identity.save_fingerprint("e5ox72jb")
        identity.set_agent_id(self.home, "anish-bot.e5ox72jb")
        identity.mark_confirmed(self.home)

        started = threading.Event()
        finish = threading.Event()

        def slow_publish():
            started.set()
            finish.wait(timeout=2)

        self.gate._publish_identities = slow_publish
        before = time.monotonic()
        self.gate.schedule_identity_setup()
        elapsed = time.monotonic() - before

        self.assertLess(elapsed, 0.5, "adoption must not wait on the publish call")
        self.assertIsNotNone(self.gate.SESSION_AGENT_ID)
        self.assertTrue(started.wait(timeout=1), "publish should still run")
        finish.set()


class DeclineTest(unittest.TestCase):
    """Declining the startup prompt means NO id — not a quiet fallback.

    It used to adopt the saved id anyway, so "no thanks" produced an addressable
    session with a queue, which makes the prompt theatre.
    """

    def setUp(self):
        self.home = tempfile.mkdtemp()
        os.environ["ANTROZOUS_HOME"] = self.home
        os.environ.pop("AGENT_ID", None)
        import mcp_gate

        self.gate = mcp_gate
        self.gate.SESSION_AGENT_ID = None
        self.gate.SESSION_DECLINED = True
        self.results = []
        self.gate.tool_result = lambda _id, text, **kw: self.results.append(
            (kw.get("is_error", False), text)
        )

    def tearDown(self):
        self.gate.SESSION_DECLINED = False
        shutil.rmtree(self.home, ignore_errors=True)
        os.environ.pop("ANTROZOUS_HOME", None)

    def test_declined_session_has_no_id(self):
        self.assertIsNone(self.gate.current_agent_id())

    def test_declined_session_cannot_send(self):
        self.gate.do_send(1, {"to_agent": "someone.aaaaaaaa", "content": "hi"})
        self.assertTrue(self.results[-1][0], "must be an error")
        self.assertIn("no antrozous agent id", self.results[-1][1])

    def test_declined_session_cannot_receive(self):
        self.gate.do_check(1, {})
        self.assertTrue(self.results[-1][0], "must be an error")

    def test_whoami_reports_the_decline(self):
        self.gate.do_whoami(1, {})
        body = json.loads(self.results[-1][1])
        self.assertIsNone(body["agent_id"])
        self.assertTrue(body["declined"])

    def test_set_identity_opts_back_in(self):
        self.gate._adopt_session_id("later.kbjz3w4a")
        self.assertEqual(self.gate.current_agent_id(), "later.kbjz3w4a")
        self.assertFalse(self.gate.SESSION_DECLINED)


class FrontDoorTests(SessionRenameTest):
    def setUp(self):
        super().setUp()
        identity.save_fingerprint("e5ox72jb")
        identity.set_agent_id(self.base, "anish-bot.e5ox72jb")

    def test_non_primary_reads_only_its_own_queue(self):
        gate = self.gate
        gate.SESSION_AGENT_ID = "anish-bot-2.e5ox72jb"
        with mock_primary(False):
            self.assertEqual(
                gate.inbox_addresses(), ["anish-bot-2.e5ox72jb"]
            )

    def test_primary_also_reads_the_front_door(self):
        gate = self.gate
        gate.SESSION_AGENT_ID = "anish-bot-2.e5ox72jb"
        with mock_primary(True):
            self.assertEqual(
                gate.inbox_addresses(),
                ["anish-bot-2.e5ox72jb", "anish-bot.e5ox72jb"],
            )

    def test_primary_does_not_duplicate_when_the_ids_match(self):
        gate = self.gate
        gate.SESSION_AGENT_ID = "anish-bot.e5ox72jb"
        with mock_primary(True):
            self.assertEqual(gate.inbox_addresses(), ["anish-bot.e5ox72jb"])


class WhoamiCopyTests(SessionRenameTest):
    def setUp(self):
        super().setUp()
        identity.save_fingerprint("e5ox72jb")
        identity.set_agent_id(self.base, "anish-bot.e5ox72jb")
        self.gate.SESSION_AGENT_ID = "anish-bot-2.e5ox72jb"

    def test_note_does_not_claim_mail_goes_out_as_the_account(self):
        out = self.gate.whoami_payload()
        self.assertNotIn("your messages go out as", json.dumps(out).lower())

    def test_share_this_is_the_front_door(self):
        out = self.gate.whoami_payload()
        self.assertEqual(out["share_this"], out["account_agent_id"])

    def test_sends_from_is_reported_and_is_the_session(self):
        out = self.gate.whoami_payload()
        self.assertEqual(out["sends_from"], out["agent_id"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
