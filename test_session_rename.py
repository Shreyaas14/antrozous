"""The startup prompt has to actually rename you.

The bug this covers: the popup asks for a name every launch, but only wrote the
SAVED default on first setup. Sends, key publishing and the alias all derive from
the account address, so after that first time a rename silently applied to nothing
you could see — you'd tell people "I'm anish-bot" while every message you sent said
anish-bot-1.
"""

import json
import os
import shutil
import tempfile
import unittest


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

    def test_later_launches_only_name_the_tab(self):
        """Anish's bug, now the documented rule rather than an accident.

        Typing a name at launch after the first run must NOT move your address —
        set_identity is the only thing that renames you.
        """
        self.reply("anish-bot-1", suggested="agent-shreyaas")
        self.identity.mark_confirmed(self.base)

        self.reply("agent-anish", suggested="anish-bot-1")
        self.assertEqual(self.saved(), "anish-bot-1.kbjz3w4a", "address must not move")
        self.assertEqual(self.gate.SESSION_AGENT_ID, "agent-anish.kbjz3w4a")

    def test_a_second_tab_names_itself_without_renaming_the_account(self):
        """Two Claude sessions on one machine need distinct session ids."""
        self.reply("anish-bot", suggested="agent-shreyaas")
        self.identity.mark_confirmed(self.base)

        self.reply(
            "scratch", suggested="anish-bot-2", peers={99999: "anish-bot.kbjz3w4a"}
        )
        self.assertEqual(self.saved(), "anish-bot.kbjz3w4a", "account must not move")
        self.assertEqual(self.gate.SESSION_AGENT_ID, "scratch.kbjz3w4a")

    def test_the_prompt_says_which_one_it_is(self):
        """The wording has to match the behaviour, or people rename nothing."""
        info = self.identity.describe(self.base)
        first, _ = self.gate._session_prompt(info, "agent-shreyaas", "kbjz3w4a", {})
        self.assertIn("FIRST run", first)
        self.assertIn("YOUR ADDRESS", first)

        self.reply("anish-bot", suggested="agent-shreyaas")
        self.identity.mark_confirmed(self.base)
        info = self.identity.describe(self.base)
        later, _ = self.gate._session_prompt(info, "anish-bot-2", "kbjz3w4a", {})
        self.assertIn("THIS TAB only", later)
        self.assertIn("set_identity", later)

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
        self.gate.tool_result = lambda _id, text, **kw: captured.update(text=text)
        self.gate._ws_url = lambda a: "wss://test/ws/" + a
        self.gate.do_whoami(1, {})
        self.assertIn("scratch.kbjz3w4a", captured["text"])
        self.assertIn("anish-bot.kbjz3w4a", captured["text"])
        self.assertIn("go out as", captured["text"])


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
