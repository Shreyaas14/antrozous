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
import select
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

import identity

GATE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mcp_gate.py")


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


class SessionRenameFixture(unittest.TestCase):
    """setUp/tearDown/helpers shared by the classes below. Deliberately carries no
    test_* methods of its own.

    SessionRenameTest used to double as this fixture AND own a full test suite, so
    every subclass (SessionAdoptionTests, FrontDoorTests, WhoamiCopyTests, ...) that
    reused its setUp also silently re-ran that whole suite under its own fixture.
    That is how a copy-only task (whoami's note wording) ended up responsible for
    fixing an unrelated publish-count assertion: WhoamiCopyTests's setUp gives the
    session and account different ids, which broke an inherited test whose literal
    expectation assumed they matched. Subclass THIS class for setUp/helpers only.
    """

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
        self.real_find_directory = self.identity.find_directory
        self.identity.find_directory = lambda: self.base

    def tearDown(self):
        # Put the module back, or the next setUp captures THIS test's stub as the
        # "real" function and every later test silently exercises a lambda.
        self.gate._publish_identities = self.real_publish_identities
        self.identity.find_directory = self.real_find_directory
        shutil.rmtree(self.home, ignore_errors=True)
        shutil.rmtree(self.base, ignore_errors=True)
        os.environ.pop("ANTROZOUS_HOME", None)
        # setUp sets this to "0" so schedule_identity_setup() doesn't fire during
        # fixture-only tests; left set, it leaks into every later test's os.environ
        # -- including a real subprocess env built from it, like
        # MigrationOfferDoesNotBlockTheReadLoopTest's -- silencing
        # notifications/initialized there too.
        os.environ.pop("ANTROZOUS_STARTUP_PROMPT", None)

    def reply(self, typed, suggested, peers=None):
        """Drive the startup prompt's answer as if the user typed `typed`."""
        self.gate._startup_pending = True
        self.gate._startup_suggested = suggested
        # Restored on cleanup -- identity is a shared module, and leaving this
        # patched escapes the module: any later test (in this file or another)
        # that calls identity.live_sessions() gets THIS test's peers lambda
        # instead of the real session registry.
        self.addCleanup(
            setattr, self.identity, "live_sessions", self.identity.live_sessions
        )
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


class SessionRenameTest(SessionRenameFixture):
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
        # All three restored on cleanup -- left patched, they leak past this test:
        # CLIENT_ELICITATION stuck True skips the "client can't confirm" guard,
        # _elicit stuck auto-accepting turns every later rename into a silent
        # yes, and tool_result stuck silent drops every later test's assertions
        # on it.
        self.addCleanup(
            setattr, self.gate, "CLIENT_ELICITATION", self.gate.CLIENT_ELICITATION
        )
        self.gate.CLIENT_ELICITATION = True
        self.addCleanup(setattr, self.gate, "_elicit", self.gate._elicit)
        self.gate._elicit = lambda prompt, schema: ("accept", {})
        self.addCleanup(setattr, self.gate, "tool_result", self.gate.tool_result)
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
        # Restored on cleanup -- left patched, every later real publish (this
        # test's tearDown does not un-stub _publish_identities, only publish_keys
        # is fixture-local here) would silently keep recording into `published`.
        self.addCleanup(setattr, self.gate, "publish_keys", self.gate.publish_keys)
        self.gate.publish_keys = lambda addr: published.append(addr) or True
        self.gate._published.clear()

        # Account and session are the same id here, so one publish per call.
        self.real_publish_identities()
        self.real_publish_identities()
        self.assertEqual(len(published), 2, "must republish, not skip")

    def test_whoami_flags_the_mismatch(self):
        self.reply("anish-bot", suggested="agent-shreyaas")
        self.identity.mark_confirmed(self.base)
        self.reply(
            "scratch", suggested="anish-bot-2", peers={99999: "anish-bot.kbjz3w4a"}
        )

        captured = {}
        # Restored on cleanup -- see the note in test_set_identity_publishes_...
        # for why leaving either of these patched leaks into later tests.
        self.addCleanup(setattr, self.gate, "tool_result", self.gate.tool_result)
        self.gate.tool_result = lambda _id, text, **kw: captured.update(text=text)
        self.addCleanup(setattr, self.gate, "_ws_url", self.gate._ws_url)
        self.gate._ws_url = lambda a: "wss://test/ws/" + a
        self.gate.do_whoami(1, {})
        self.assertIn("scratch.kbjz3w4a", captured["text"])
        self.assertIn("anish-bot.kbjz3w4a", captured["text"])
        self.assertIn("sends as", captured["text"])


class SessionAdoptionTests(SessionRenameFixture):
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


class FrontDoorTests(SessionRenameFixture):
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


class WhoamiCopyTests(SessionRenameFixture):
    def setUp(self):
        super().setUp()
        identity.save_fingerprint("e5ox72jb")
        identity.set_agent_id(self.base, "anish-bot.e5ox72jb")
        self.gate.SESSION_AGENT_ID = "anish-bot-2.e5ox72jb"
        # whoami_payload() mints a ws ticket per address via a real POST unless
        # stubbed -- harmless against a dead relay, but a developer running one
        # locally would get live ticket mints out of a unit test. Restored on
        # cleanup so it does not leak past this class into later tests.
        self.addCleanup(setattr, self.gate, "_ws_url", self.gate._ws_url)
        self.gate._ws_url = lambda a: "wss://test/ws/" + a

    def test_note_does_not_claim_mail_goes_out_as_the_account(self):
        out = self.gate.whoami_payload()
        self.assertNotIn("your messages go out as", json.dumps(out).lower())

    def test_share_this_is_the_front_door(self):
        out = self.gate.whoami_payload()
        self.assertEqual(out["share_this"], out["account_agent_id"])

    def test_sends_from_is_reported_and_is_the_session(self):
        out = self.gate.whoami_payload()
        self.assertEqual(out["sends_from"], "anish-bot-2.e5ox72jb")
        self.assertNotEqual(out["sends_from"], out["share_this"])

    def test_env_override_note_names_the_shadowed_id_not_the_env_id(self):
        """Regression for F1's sibling bug: the $AGENT_ID note's guard compared
        info["agent_id"] (== env, by construction) against agent_id (== env, via
        current_agent_id()'s own env check) -- always False, so the note never
        rendered; and had it rendered, it would have named the env id back at the
        user instead of the saved id it claims to name.
        """
        identity.set_agent_id(self.base, "saved.e5ox72jb")
        with _env(AGENT_ID="pinned.e5ox72jb"):
            out = self.gate.whoami_payload()
        self.assertIn("note", out)
        self.assertIn("saved.e5ox72jb", out["note"])

    def test_non_primary_note_still_names_the_front_door(self):
        """A non-primary session used to lose the front-door advice entirely: the
        second note branch overwrote out["note"] instead of adding to it, dropping
        the "give people X" / "replies come back here" half.
        """
        with mock_primary(False):
            out = self.gate.whoami_payload()
        self.assertIn("drains its own queue", out["note"])
        self.assertIn("come back to", out["note"])
        self.assertIn("primary slot", out["note"].lower())


class SetIdentityAccountTests(SessionRenameFixture):
    """set_identity renames the ACCOUNT -- the stem session ids derive from --
    and nothing else. A derived, ephemeral, never-handed-out session id has
    nothing worth renaming, and renaming it out from under a primary session
    would break the private-room guarantee (see mcp_gate.inbox_addresses)."""

    def rename_to(self, name, scope="global"):
        real = self.gate._elicit
        self.addCleanup(
            setattr, self.gate, "CLIENT_ELICITATION", self.gate.CLIENT_ELICITATION
        )
        self.gate.CLIENT_ELICITATION = True
        self.gate._elicit = lambda message, schema=None: (
            "accept",
            {"agent_id": "%s.kbjz3w4a" % name},
        )
        try:
            self.gate.do_set_identity(
                "rid-1", {"agent_id": "%s.kbjz3w4a" % name, "scope": scope}
            )
        finally:
            self.gate._elicit = real

    def test_rename_writes_the_account_name(self):
        self.rename_to("newname")
        record = identity._read_json(identity._global_path())
        self.assertEqual(record["account_name"], "newname")

    def test_rename_does_not_change_this_session_id(self):
        before = self.gate.current_agent_id()
        self.rename_to("newname")
        self.assertEqual(self.gate.current_agent_id(), before)
        # Stronger than the line above: this also fails a "session got pinned
        # to the stale ACCOUNT address" implementation that happens to equal
        # `before` by coincidence of this fixture's fresh setup -- the id must
        # not just be unchanged, it must not have become the (new) account
        # address either.
        self.assertNotEqual(self.gate.current_agent_id(), self.gate.account_agent_id())

    def test_project_scope_rename_does_not_touch_the_global_account_name(self):
        """set_account_name always writes _global_path(). A project-scoped
        rename must not call it at all: account_name is the device-wide stem
        every OTHER directory's sessions derive their ids from, and a project
        directory renaming its own separate identity has no business moving
        it out from under every other directory on the machine.
        """
        identity.set_agent_id(self.base, "globalacct.kbjz3w4a")
        identity.set_account_name("globalacct")

        self.rename_to("projname", scope="project")

        record = identity._read_json(identity._global_path())
        self.assertEqual(record["agent_id"], "globalacct.kbjz3w4a")
        self.assertEqual(record["account_name"], "globalacct")
        # The project file itself DID get the new id -- this isn't a no-op,
        # just correctly scoped.
        self.assertEqual(
            identity.describe(self.base)["agent_id"], "projname.kbjz3w4a"
        )

    def test_account_name_write_failure_is_reported_not_raised(self):
        """set_account_name is the only unguarded write in do_set_identity --
        its neighbour set_agent_id is wrapped in except OSError. Unwrapped, an
        OSError here (e.g. a full disk) would propagate out of tools/call
        dispatch and take the whole gate down, AFTER agent_id was already
        written to disk.
        """
        self.addCleanup(
            setattr, self.identity, "set_account_name", self.identity.set_account_name
        )
        self.identity.set_account_name = lambda name: (_ for _ in ()).throw(
            OSError("disk full")
        )
        results = []
        self.addCleanup(setattr, self.gate, "tool_result", self.gate.tool_result)
        self.gate.tool_result = lambda _id, text, **kw: results.append(
            (text, kw.get("is_error", False))
        )

        self.rename_to("newname")  # must not raise

        self.assertTrue(results, "do_set_identity must still report something")
        self.assertTrue(results[-1][1], "must be reported as an error")
        self.assertEqual(
            identity._read_json(identity._global_path())["agent_id"],
            "newname.kbjz3w4a",
            "agent_id had already landed on disk before the failing write",
        )

    def test_session_id_survives_an_account_name_write_that_raises_oserror(self):
        """Regression for a bug introduced by the previous fix for this exact
        crash: the account_name failure branch used to `return` BEFORE the
        session re-pin. By the time set_account_name runs, identity.set_agent_id
        has already written `canonical` to the global record, so a session
        that never adopted an id of its own (SESSION_AGENT_ID is None, not
        declined -- the exact shape the re-pin exists for) falls through
        current_agent_id() -> identity.resolve_agent_id(), which now reads the
        NEW id -- silently renaming this session's own address on a rename
        that only half-completed.
        """
        identity.set_agent_id(self.base, "oldname.kbjz3w4a")
        self.assertEqual(self.gate.current_agent_id(), "oldname.kbjz3w4a")

        self.addCleanup(
            setattr, self.identity, "set_account_name", self.identity.set_account_name
        )
        self.identity.set_account_name = lambda name: (_ for _ in ()).throw(
            OSError("disk full")
        )

        self.rename_to("newname")

        self.assertEqual(
            self.gate.current_agent_id(),
            "oldname.kbjz3w4a",
            "this session must keep its pre-rename address even though the "
            "account id it was pinning against was already rewritten",
        )

    def test_session_id_survives_an_account_name_write_that_raises_valueerror(self):
        """set_account_name's ValueError is independently reachable, not just
        a theoretical catch-all alongside OSError:
        identity.agent_name("a.bc.efgh1234") returns the whole string
        unchanged (it fails split_agent_id's fingerprint check, since "1" is
        not in FINGERPRINT_RE's alphabet), and normalize_name of that returns
        None because its first dot-delimited segment ("a") is a single
        character -- so the REAL set_account_name (no stubbing needed here)
        raises for a canonical that normalize_agent_id had already accepted
        and identity.set_agent_id had already written to disk.
        """
        identity.set_agent_id(self.base, "oldname.kbjz3w4a")
        self.assertEqual(self.gate.current_agent_id(), "oldname.kbjz3w4a")

        real_elicit = self.gate._elicit
        self.addCleanup(
            setattr, self.gate, "CLIENT_ELICITATION", self.gate.CLIENT_ELICITATION
        )
        self.gate.CLIENT_ELICITATION = True
        self.gate._elicit = lambda message, schema=None: (
            "accept",
            {"agent_id": "a.bc.efgh1234"},
        )
        try:
            self.gate.do_set_identity("rid-1", {"agent_id": "a.bc.efgh1234"})
        finally:
            self.gate._elicit = real_elicit

        self.assertEqual(
            identity._read_json(identity._global_path())["agent_id"],
            "a.bc.efgh1234",
            "sanity check: the agent_id write really did land despite the "
            "account_name write raising",
        )
        self.assertEqual(
            self.gate.current_agent_id(),
            "oldname.kbjz3w4a",
            "this session must keep its pre-rename address even though the "
            "account id it was pinning against was already rewritten",
        )

    def test_prompt_says_the_alias_does_not_move(self):
        """Exercises the RENAME branch specifically (an already-set-up
        account), not the first-run branch -- there is no alias "already
        claimed" to talk about on a first run, and this task rewrote the
        rename branch's copy, not the first-run branch's.
        """
        identity.set_agent_id(self.base, "oldname.kbjz3w4a")
        prompt, _ = self.gate._identity_prompt(
            identity.describe(self.base), "newname", "global", False
        )
        self.assertIn("CHANGE YOUR ANTROZOUS AGENT ID?", prompt)
        self.assertIn(
            "does NOT move the alias you already claimed",
            prompt,
            "must be the specific rename notice, not just the word 'alias' "
            "appearing anywhere",
        )

    def test_first_run_prompt_says_nothing_about_an_alias(self):
        """The alias-does-not-move notice is only true of an actual rename --
        a first run has no alias already claimed under any name yet."""
        prompt, _ = self.gate._identity_prompt(
            identity.describe(self.home), "newname", "global", False
        )
        self.assertIn("NAME YOUR ANTROZOUS AGENT", prompt)
        self.assertNotIn("alias", prompt.lower())

    def test_prompt_does_not_claim_the_old_address_is_always_orphaned(self):
        """Regression: a prior rewording of this prompt asserted the old
        address "lands in a queue nothing drains automatically" as a flat
        fact. False whenever the renaming session never adopted an id of its
        own: do_set_identity pins that session back onto exactly the address
        being renamed away from (see test_rename_does_not_change_this_session_id),
        so THAT session goes right on draining it -- directly contradicting
        the approval message printed seconds later ("this session itself
        keeps sending and receiving as %s"). The copy now names both possible
        outcomes instead of asserting the one that doesn't always hold.
        """
        identity.set_agent_id(self.base, "oldname.kbjz3w4a")
        prompt, _ = self.gate._identity_prompt(
            identity.describe(self.base), "newname", "global", False
        )
        self.assertNotIn("lands in a queue nothing drains automatically", prompt)
        self.assertIn("whichever session already answers to that address", prompt)


class ProjectOverrideSessionTests(SessionRenameFixture):
    """A directory that opted out of the account must also SEND as itself.

    Regression: resume_or_assign_session_id() built the session id from
    identity.account_name(), which reads the global record only, while
    account_agent_id() honours the project tier -- so in a directory with
    .antrozous/identity.json the front door was the project id and every outbound
    from_agent carried the GLOBAL account's stem. Nothing covered session
    derivation under a project override.
    """

    def setUp(self):
        super().setUp()
        identity.save_fingerprint("e5ox72jb")
        identity.set_agent_id(self.home, "anish-bot.e5ox72jb")
        identity.set_account_name("anish-bot")
        identity.set_agent_id(self.base, "agent-foo-ab12.e5ox72jb", scope="project")

    def test_session_id_is_numbered_from_the_project_name(self):
        with _env(CLAUDE_CODE_SESSION_ID="sess-proj"):
            chosen = self.gate.resume_or_assign_session_id()
        self.assertEqual(chosen, "agent-foo-ab12-1.e5ox72jb")

    def test_the_return_address_matches_the_front_door(self):
        """The user-visible defect: the address people reply to and the address the
        mail comes from named two different agents."""
        with _env(CLAUDE_CODE_SESSION_ID="sess-proj"):
            chosen = self.gate.resume_or_assign_session_id()
        self.assertEqual(self.gate.account_agent_id(), "agent-foo-ab12.e5ox72jb")
        self.assertTrue(
            chosen.startswith("agent-foo-ab12-"),
            "session id %r must be built from the project stem" % (chosen,),
        )

    def test_the_registered_record_carries_the_project_stem(self):
        with _env(CLAUDE_CODE_SESSION_ID="sess-proj"):
            self.gate.resume_or_assign_session_id()
            record = identity.session_records()["sess-proj"]
        self.assertEqual(record["agent_id"], "agent-foo-ab12-1.e5ox72jb")


class MigrationTests(SessionRenameFixture):
    """Existing installs may have an account name that already ends in an
    ordinal (the author's own machine has anish-bot-1.e5ox72jb) -- a session
    number typed into the old per-session popup before every session derived
    its own number automatically. Left alone, sessions become
    anish-bot-1-1, anish-bot-1-2. migration_candidate()/apply_account_migration()
    offer, once, to strip it -- and always reseed the ordinal counter so a
    rename cannot hand out a number some other queue already uses.
    """

    def test_trailing_ordinal_is_offered_for_stripping(self):
        identity.set_agent_id(self.home, "anish-bot-1.e5ox72jb")
        self.assertEqual(self.gate.migration_candidate(), "anish-bot")

    def test_a_clean_name_needs_no_migration(self):
        identity.set_agent_id(self.home, "anish-bot.e5ox72jb")
        self.assertIsNone(self.gate.migration_candidate())

    def test_a_name_that_is_only_digits_is_left_alone(self):
        identity.set_agent_id(self.home, "agent-42.e5ox72jb")
        self.assertEqual(self.gate.migration_candidate(), "agent")

    def test_no_account_name_yet_needs_no_migration(self):
        self.assertIsNone(self.gate.migration_candidate())

    def test_an_explicit_account_name_already_stops_the_offer(self):
        """The second condition migration_candidate() checks: an explicit
        account_name -- even one still ending in a number -- means a decision
        was already recorded, and the offer must not repeat."""
        identity.set_agent_id(self.home, "anish-bot-1.e5ox72jb")
        identity.set_account_name("anish-bot-1")
        self.assertIsNone(self.gate.migration_candidate())

    def test_declining_keeps_the_name_verbatim(self):
        identity.set_agent_id(self.home, "anish-bot-1.e5ox72jb")
        self.gate.apply_account_migration(accepted=False)
        self.assertEqual(identity.account_name(), "anish-bot-1")

    def test_declining_stops_the_offer_repeating(self):
        """Recording the CURRENT name on decline is what makes this a
        one-time offer instead of one every launch."""
        identity.set_agent_id(self.home, "anish-bot-1.e5ox72jb")
        self.gate.apply_account_migration(accepted=False)
        self.assertIsNone(self.gate.migration_candidate())

    def test_accepting_strips_and_seeds_the_counter(self):
        identity.save_fingerprint("e5ox72jb")
        identity.set_agent_id(self.home, "anish-bot-1.e5ox72jb")
        os.makedirs(identity.sessions_dir(), exist_ok=True)
        with open(os.path.join(identity.sessions_dir(), "old.json"), "w") as f:
            json.dump({"agent_id": "anish-bot-4.e5ox72jb", "pid": None}, f)
        self.gate.apply_account_migration(accepted=True)
        self.assertEqual(identity.account_name(), "anish-bot")
        self.assertEqual(identity.next_ordinal(), 5)

    def test_declining_also_seeds_the_counter(self):
        """apply_account_migration always seeds the counter, whichever way
        the answer went -- a decline still needs the ordinal high-water mark
        raised above whatever ordinals earlier sessions already used."""
        identity.set_agent_id(self.home, "anish-bot-1.e5ox72jb")
        os.makedirs(identity.sessions_dir(), exist_ok=True)
        with open(os.path.join(identity.sessions_dir(), "old.json"), "w") as f:
            json.dump({"agent_id": "anish-bot-1-3.e5ox72jb", "pid": None}, f)
        self.gate.apply_account_migration(accepted=False)
        self.assertEqual(identity.next_ordinal(), 4)

    def test_apply_migration_writes_through_the_locked_helper(self):
        """Must go through identity.set_account_name(), which takes the
        identity lock guarding session_counter -- not an unlocked
        read/modify/write of the global record, which could lose a
        concurrent next_ordinal() increment and hand the same ordinal to two
        sessions."""
        identity.set_agent_id(self.home, "anish-bot-1.e5ox72jb")
        calls = []
        self.addCleanup(
            setattr, self.identity, "set_account_name", self.identity.set_account_name
        )
        self.identity.set_account_name = lambda name: calls.append(name) or name
        self.gate.apply_account_migration(accepted=True)
        self.assertEqual(calls, ["anish-bot"])

    def test_no_decision_records_nothing_but_still_seeds(self):
        """accepted=None -- a dismissed/cancelled/unanswered popup -- is not a
        decision: nothing is recorded (the pinned RED check below is what
        the original brief's collapsed decline/cancel branch would have
        failed), so the offer returns next launch, but the counter is still
        raised above every ordinal already in use."""
        identity.set_agent_id(self.home, "anish-bot-1.e5ox72jb")
        os.makedirs(identity.sessions_dir(), exist_ok=True)
        with open(os.path.join(identity.sessions_dir(), "old.json"), "w") as f:
            json.dump({"agent_id": "anish-bot-1-3.e5ox72jb", "pid": None}, f)

        self.gate.apply_account_migration(accepted=None)

        self.assertEqual(identity.account_name(), "anish-bot-1")
        self.assertFalse(identity.has_explicit_account_name())
        self.assertIsNotNone(self.gate.migration_candidate(), "must be offered again")
        self.assertEqual(identity.next_ordinal(), 4)

    def test_offer_without_elicitation_declines_automatically(self):
        identity.set_agent_id(self.home, "anish-bot-1.e5ox72jb")
        self.addCleanup(
            setattr, self.gate, "CLIENT_ELICITATION", self.gate.CLIENT_ELICITATION
        )
        self.gate.CLIENT_ELICITATION = False
        self.gate.offer_account_migration()
        self.assertEqual(identity.account_name(), "anish-bot-1")
        self.assertIsNone(self.gate.migration_candidate())

    def test_offer_does_nothing_without_a_candidate(self):
        """A clean name must not even send an elicitation."""
        identity.set_agent_id(self.home, "anish-bot.e5ox72jb")
        self.addCleanup(
            setattr, self.gate, "CLIENT_ELICITATION", self.gate.CLIENT_ELICITATION
        )
        self.gate.CLIENT_ELICITATION = True
        sent = []
        self.addCleanup(setattr, self.gate, "send", self.gate.send)
        self.gate.send = lambda obj: sent.append(obj)
        self.gate.offer_account_migration()
        self.assertEqual(sent, [])

    def _send_migration_offer(self):
        """Trigger offer_account_migration() with CLIENT_ELICITATION on,
        capturing the elicitation/create message it sends via `send()`
        instead of blocking on it -- the whole point of the fire-and-forget
        redesign this task required. Returns the captured message. Cleans up
        `send`, CLIENT_ELICITATION and the answer-timeout Timer automatically.
        """
        self.addCleanup(
            setattr, self.gate, "CLIENT_ELICITATION", self.gate.CLIENT_ELICITATION
        )
        self.gate.CLIENT_ELICITATION = True
        sent = []
        self.addCleanup(setattr, self.gate, "send", self.gate.send)
        self.gate.send = lambda obj: sent.append(obj)
        self.gate.offer_account_migration()
        self.assertEqual(len(sent), 1, "must send exactly one elicitation")
        self.assertEqual(sent[0]["method"], "elicitation/create")
        # Always resolve the pending offer before the test ends, whether or
        # not the test itself answers it: a real threading.Timer is running
        # in the background (offer_account_migration started it), and if it
        # is left alive past this test it can fire _migration_timeout() on a
        # LATER test's own unrelated pending offer.
        self.addCleanup(self._force_resolve_migration)
        return sent[0]

    def _force_resolve_migration(self):
        if self.gate._migration_pending:
            self.gate._migration_timeout()
        if self.gate._migration_timer is not None:
            self.gate._migration_timer.cancel()

    def test_offer_with_elicitation_asks_and_applies_acceptance(self):
        identity.set_agent_id(self.home, "anish-bot-1.e5ox72jb")
        msg = self._send_migration_offer()
        self.assertTrue(self.gate._migration_pending)
        self.assertEqual(identity.account_name(), "anish-bot-1", "unresolved so far")

        handled = self.gate._handle_migration_reply(
            {"id": msg["id"], "result": {"action": "accept", "content": {}}}
        )

        self.assertTrue(handled)
        self.assertFalse(self.gate._migration_pending)
        self.assertEqual(identity.account_name(), "anish-bot")

    def test_offer_with_elicitation_respects_explicit_decline(self):
        identity.set_agent_id(self.home, "anish-bot-1.e5ox72jb")
        msg = self._send_migration_offer()

        self.gate._handle_migration_reply(
            {"id": msg["id"], "result": {"action": "decline", "content": {}}}
        )

        self.assertEqual(identity.account_name(), "anish-bot-1")
        self.assertTrue(identity.has_explicit_account_name())
        self.assertIsNone(self.gate.migration_candidate(), "must not repeat")

    def test_cancel_is_not_recorded_as_a_decision(self):
        """Important finding #2: collapsing cancel/dismiss into decline meant
        a client that simply REJECTS the elicitation request (which is
        exactly what happens when it discards the request outright) would
        permanently and silently opt the account out of ever being offered
        the migration again -- indistinguishable in the record from a user
        who typed "no". do_set_identity keeps these separate on purpose (see
        its "It will be offered again next session" branch); this must too.
        """
        identity.set_agent_id(self.home, "anish-bot-1.e5ox72jb")
        msg = self._send_migration_offer()

        self.gate._handle_migration_reply(
            {"id": msg["id"], "result": {"action": "cancel", "content": {}}}
        )

        self.assertEqual(identity.account_name(), "anish-bot-1")
        self.assertFalse(
            identity.has_explicit_account_name(),
            "a cancel must not be recorded as though the user had decided",
        )
        self.assertIsNotNone(self.gate.migration_candidate(), "must be offered again")

    def test_a_client_error_response_is_not_recorded_as_a_decision(self):
        """The other half of finding #2's compounding scenario: a client
        that rejects elicitation/create outright sends back an error, not an
        explicit decline -- same non-decision treatment applies."""
        identity.set_agent_id(self.home, "anish-bot-1.e5ox72jb")
        msg = self._send_migration_offer()

        self.gate._handle_migration_reply(
            {"id": msg["id"], "error": {"code": -32601, "message": "not supported"}}
        )

        self.assertFalse(identity.has_explicit_account_name())
        self.assertIsNotNone(self.gate.migration_candidate())

    def test_a_late_reply_after_the_timeout_is_ignored(self):
        """Whichever of the reply or the timeout fires first wins; the other
        must not re-apply a second, possibly contradictory, decision."""
        identity.set_agent_id(self.home, "anish-bot-1.e5ox72jb")
        msg = self._send_migration_offer()

        self.gate._migration_timeout()
        self.assertFalse(identity.has_explicit_account_name())

        handled = self.gate._handle_migration_reply(
            {"id": msg["id"], "result": {"action": "accept", "content": {}}}
        )

        self.assertFalse(handled, "a reply after the timeout must not be applied")
        self.assertEqual(identity.account_name(), "anish-bot-1")
        self.assertFalse(
            identity.has_explicit_account_name(), "the late accept must not land"
        )

    def test_timeout_with_no_reply_still_finishes_identity_setup(self):
        """Non-negotiable requirement: if the popup never gets an answer at
        all, this session must still become addressable -- a migration that
        cannot fire is a missed convenience, a session that never gets an id
        because a popup went unanswered is a much worse bug."""
        identity.save_fingerprint("e5ox72jb")
        identity.set_agent_id(self.home, "anish-bot-1.e5ox72jb")
        self._send_migration_offer()

        self.gate._migration_timeout()

        self.assertIsNotNone(self.gate.SESSION_AGENT_ID)
        self.assertFalse(identity.has_explicit_account_name())
        self.assertIsNotNone(self.gate.migration_candidate())

    def test_popup_names_both_addresses_and_says_the_alias_does_not_move(self):
        """Four reviews in this plan found user-facing copy that contradicted
        the code. The truthful claim here: people who already have the old
        (bare) name still reach this account, because the relay binds an
        alias to a fingerprint, first claim wins, and it is never
        reassigned -- so accepting does not move it anywhere. Also checks
        the understatement a later review caught: that mail is not silently
        lost, but it does not arrive directly either -- it has to be
        surfaced via check_inbox's other-queues listing."""
        identity.save_fingerprint("e5ox72jb")
        identity.set_agent_id(self.home, "anish-bot-1.e5ox72jb")

        msg = self._send_migration_offer()

        prompt = msg["params"]["message"]
        self.assertIn("anish-bot-1.e5ox72jb", prompt)
        self.assertIn("anish-bot.e5ox72jb", prompt)
        self.assertIn("first claim wins", prompt)
        self.assertIn("does not move", prompt.lower())
        self.assertIn("check_inbox", prompt)
        self.assertIn("does not poll", prompt.lower())

    def test_schedule_identity_setup_defers_the_offer_behind_startup_delay(self):
        """The migration popup is elicitation sent from the same
        notifications/initialized handler as the first-run popup, so it is
        just as subject to the "discards elicitation received during
        initialization" client bug STARTUP_DELAY exists for -- it must be
        deferred behind the SAME Timer, not sent inline."""
        identity.set_agent_id(self.home, "anish-bot-1.e5ox72jb")
        identity.mark_confirmed(self.home)
        self.addCleanup(
            setattr, self.gate, "CLIENT_ELICITATION", self.gate.CLIENT_ELICITATION
        )
        self.gate.CLIENT_ELICITATION = True
        self.addCleanup(setattr, self.gate, "STARTUP_DELAY", self.gate.STARTUP_DELAY)
        # Large enough that it cannot plausibly fire before this whole test
        # process exits (a daemon Timer thread dies with the interpreter
        # regardless), so there is no real risk of a stray real elicitation
        # firing later against already-restored module state.
        self.gate.STARTUP_DELAY = 3600.0
        sent = []
        self.addCleanup(setattr, self.gate, "send", self.gate.send)
        self.gate.send = lambda obj: sent.append(obj)

        self.gate.schedule_identity_setup()

        self.assertEqual(sent, [], "must not send before the delay elapses")
        self.assertIsNone(self.gate.SESSION_AGENT_ID, "must not adopt before deciding")

    def test_schedule_identity_setup_seeds_before_taking_an_ordinal(self):
        """Regression for the ordering this whole task exists to guarantee:
        the migration decision (and its reseed) must land BEFORE
        resume_or_assign_session_id() takes this session's own ordinal, or a
        freshly-migrated stem could hand out a number that already has a
        live queue on the relay under the OLD stem's numbering."""
        identity.save_fingerprint("e5ox72jb")
        identity.set_agent_id(self.home, "anish-bot-1.e5ox72jb")
        identity.mark_confirmed(self.home)
        os.makedirs(identity.sessions_dir(), exist_ok=True)
        with open(os.path.join(identity.sessions_dir(), "old.json"), "w") as f:
            json.dump({"agent_id": "anish-bot-1-3.e5ox72jb", "pid": None}, f)

        self.addCleanup(
            setattr, self.gate, "CLIENT_ELICITATION", self.gate.CLIENT_ELICITATION
        )
        self.gate.CLIENT_ELICITATION = True
        # STARTUP_DELAY<=0 keeps schedule_identity_setup's dispatch inline
        # (see its own "else" branch) rather than behind a real Timer, so
        # this test stays synchronous and deterministic -- covered
        # separately by test_schedule_identity_setup_defers_the_offer_....
        self.addCleanup(setattr, self.gate, "STARTUP_DELAY", self.gate.STARTUP_DELAY)
        self.gate.STARTUP_DELAY = 0
        sent = []
        self.addCleanup(setattr, self.gate, "send", self.gate.send)
        self.gate.send = lambda obj: sent.append(obj)

        with _env(CLAUDE_CODE_SESSION_ID="sess-new"):
            self.gate.schedule_identity_setup()

        self.assertEqual(len(sent), 1)
        self.assertTrue(self.gate._migration_pending)
        self.assertIsNone(self.gate.SESSION_AGENT_ID, "not adopted until answered")

        self.gate._handle_migration_reply(
            {"id": sent[0]["id"], "result": {"action": "accept", "content": {}}}
        )

        self.assertEqual(identity.account_name(), "anish-bot")
        self.assertEqual(self.gate.SESSION_AGENT_ID, "anish-bot-4.e5ox72jb")


class MigrationOfferDoesNotBlockTheReadLoopTest(unittest.TestCase):
    """Regression for the bug none of the direct-call tests above can catch:
    the migration offer used to call the BLOCKING _elicit(), which reads
    from the SAME stdin the main read loop reads from. Any other request
    that arrived while it waited -- tools/list included -- was silently
    discarded by _elicit's own inner loop (it only recognizes its own reply,
    startup-reply messages, and pings), never answered.

    Calling offer_account_migration() directly, as every test above does,
    cannot observe this: it never drives the real read loop those other
    requests travel through, so nothing in this file's other tests would
    have failed against the unfixed, blocking version. Only spawning the
    actual gate process and feeding it real, concurrent JSON-RPC traffic
    exercises the code path where the bug lived -- this test would hang
    (bounded by the timeouts below, so it fails rather than truly hanging)
    against the pre-fix code, and passes against the fire-and-forget fix.
    """

    def setUp(self):
        self.home = tempfile.mkdtemp()
        saved_home = os.environ.get("ANTROZOUS_HOME")
        os.environ["ANTROZOUS_HOME"] = self.home
        try:
            identity.set_agent_id(self.home, "anish-bot-1.e5ox72jb")
            identity.mark_confirmed(self.home)
        finally:
            if saved_home is None:
                os.environ.pop("ANTROZOUS_HOME", None)
            else:
                os.environ["ANTROZOUS_HOME"] = saved_home

        env = dict(os.environ, ANTROZOUS_HOME=self.home)
        env.pop("AGENT_ID", None)
        # Fire the offer immediately (no real startup delay) and give this
        # test itself far longer than it needs to answer, so the ONLY way
        # the fallback answer-timeout can fire is a genuine regression.
        env["ANTROZOUS_STARTUP_DELAY"] = "0"
        env["ANTROZOUS_MIGRATION_TIMEOUT"] = "30"
        self.proc = subprocess.Popen(
            [sys.executable, GATE_PATH],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            env=env,
        )

    def tearDown(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.kill()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=5)
        except Exception:
            pass
        shutil.rmtree(self.home, ignore_errors=True)

    def _send(self, obj):
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()

    def _recv(self, timeout):
        """One JSON-RPC line, or None if none arrives within `timeout`
        seconds -- bounded so a real regression (the loop hanging) fails
        this test instead of hanging the whole suite."""
        r, _, _ = select.select([self.proc.stdout], [], [], timeout)
        if not r:
            return None
        line = self.proc.stdout.readline()
        return json.loads(line) if line else None

    def test_tools_list_is_answered_while_the_migration_popup_is_pending(self):
        self._send(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {"elicitation": {}},
                    "clientInfo": {"name": "test", "version": "0"},
                },
            }
        )
        init_reply = self._recv(timeout=5)
        self.assertIsNotNone(init_reply, "gate did not answer initialize")
        self.assertEqual(init_reply["result"]["serverInfo"]["name"], "antrozous-gate")

        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

        # Ask for tools/list immediately, BEFORE the migration popup is
        # answered. Under the old blocking design this request is consumed
        # and silently dropped inside offer_account_migration's own _elicit
        # call -- this test would then time out waiting for it.
        self._send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})

        seen_elicit_id = None
        seen_tools_list = False
        for _ in range(10):
            if seen_tools_list and seen_elicit_id is not None:
                break
            m = self._recv(timeout=3)
            if m is None:
                continue
            if m.get("method") == "elicitation/create":
                seen_elicit_id = m["id"]
            elif m.get("id") == 2:
                seen_tools_list = True
                self.assertIn("tools", m.get("result", {}))

        self.assertTrue(
            seen_tools_list,
            "tools/list was never answered -- the main read loop is blocked",
        )
        self.assertIsNotNone(seen_elicit_id, "the migration popup was never sent")

        # Answer it so the process can exit cleanly rather than idling on
        # its own answer-timeout Timer.
        self._send(
            {
                "jsonrpc": "2.0",
                "id": seen_elicit_id,
                "result": {"action": "decline", "content": {}},
            }
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
