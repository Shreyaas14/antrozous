import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts"))

import listener_state

SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "scripts", "listener_state.py"
)


class ListenerStateTest(unittest.TestCase):
    """The listener flag lives in ANTROZOUS_HOME, so every test redirects it at a
    temp dir rather than touching the developer's real ~/.antrozous."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = os.path.join(self._tmp.name, "home")
        os.makedirs(self.home)
        self._saved = os.environ.get("ANTROZOUS_HOME")
        os.environ["ANTROZOUS_HOME"] = self.home
        self.addCleanup(self._tmp.cleanup)
        self.addCleanup(self._restore)

    def _restore(self):
        if self._saved is None:
            os.environ.pop("ANTROZOUS_HOME", None)
        else:
            os.environ["ANTROZOUS_HOME"] = self._saved

    def path(self):
        return os.path.join(self.home, "listener.json")

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, SCRIPT, *args],
            capture_output=True,
            text=True,
            env=dict(os.environ, ANTROZOUS_HOME=self.home),
        )


class DefaultStateTests(ListenerStateTest):
    def test_not_listening_when_no_file(self):
        self.assertFalse(listener_state.is_listening())
        self.assertEqual(listener_state.read_state(), {})

    def test_corrupt_file_reads_as_not_listening(self):
        with open(self.path(), "w") as f:
            f.write("{not json")
        self.assertFalse(listener_state.is_listening())

    def test_clear_on_missing_file_is_a_noop(self):
        listener_state.clear_listening()  # must not raise
        self.assertFalse(listener_state.is_listening())


class SetAndClearTests(ListenerStateTest):
    def test_set_records_agent_and_timestamp(self):
        record = listener_state.set_listening("anish-bot.e5ox72jb")
        self.assertTrue(listener_state.is_listening())
        self.assertEqual(record["agent_id"], "anish-bot.e5ox72jb")
        self.assertTrue(record["started_at"])
        self.assertTrue(os.path.exists(self.path()))

    def test_state_survives_a_fresh_read(self):
        listener_state.set_listening("bob.aaaaaaaa")
        self.assertEqual(listener_state.read_state()["agent_id"], "bob.aaaaaaaa")

    def test_rearming_updates_agent_but_keeps_started_at(self):
        first = listener_state.set_listening("bob.aaaaaaaa")
        second = listener_state.set_listening("carol.bbbbbbbb")
        self.assertEqual(second["agent_id"], "carol.bbbbbbbb")
        self.assertEqual(second["started_at"], first["started_at"])

    def test_clear_stops_listening(self):
        listener_state.set_listening("bob.aaaaaaaa")
        listener_state.clear_listening()
        self.assertFalse(listener_state.is_listening())
        self.assertFalse(os.path.exists(self.path()))

    def test_set_requires_an_agent_id(self):
        with self.assertRaises(ValueError):
            listener_state.set_listening("")


class IsolationTests(ListenerStateTest):
    def test_flag_follows_antrozous_home(self):
        listener_state.set_listening("bob.aaaaaaaa")
        other = os.path.join(self._tmp.name, "other")
        os.makedirs(other)
        os.environ["ANTROZOUS_HOME"] = other
        self.assertFalse(listener_state.is_listening())


class CliTests(ListenerStateTest):
    def test_on_then_status_reports_listening(self):
        self.assertEqual(self.run_cli("on", "bob.aaaaaaaa").returncode, 0)
        result = self.run_cli("status")
        self.assertEqual(result.returncode, 0)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["listening"])
        self.assertEqual(payload["agent_id"], "bob.aaaaaaaa")

    def test_status_on_clean_home_reports_not_listening(self):
        result = self.run_cli("status")
        self.assertEqual(result.returncode, 0)
        self.assertFalse(json.loads(result.stdout)["listening"])

    def test_off_clears(self):
        self.run_cli("on", "bob.aaaaaaaa")
        self.assertEqual(self.run_cli("off").returncode, 0)
        self.assertFalse(json.loads(self.run_cli("status").stdout)["listening"])

    def test_on_without_agent_id_fails_loudly(self):
        result = self.run_cli("on")
        self.assertNotEqual(result.returncode, 0)

    def test_unknown_command_fails_loudly(self):
        self.assertNotEqual(self.run_cli("frobnicate").returncode, 0)


HOOK = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "scripts", "bootstrap_identity.py"
)


class HookResumeTests(ListenerStateTest):
    """The SessionStart hook is what brings a listener back after a restart."""

    def run_hook(self, **env):
        result = subprocess.run(
            [sys.executable, HOOK],
            capture_output=True,
            text=True,
            env=dict(os.environ, ANTROZOUS_HOME=self.home, USER="testuser", **env),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def context_of(self, payload):
        return (payload.get("hookSpecificOutput") or {}).get("additionalContext", "")

    def test_no_resume_when_flag_is_off(self):
        payload = self.run_hook(AGENT_ID="")
        self.assertNotIn("listener", payload["systemMessage"].lower())
        self.assertNotIn("ANTROZOUS LISTENER", self.context_of(payload))

    def test_resume_directive_when_flag_is_on(self):
        listener_state.set_listening("bob.aaaaaaaa")
        payload = self.run_hook(AGENT_ID="")
        self.assertIn("listener", payload["systemMessage"].lower())
        self.assertIn("bob.aaaaaaaa", payload["systemMessage"])
        context = self.context_of(payload)
        self.assertIn("ANTROZOUS LISTENER", context)
        self.assertIn("antrozous-inbox", context)

    def test_resume_also_fires_on_the_env_pinned_path(self):
        listener_state.set_listening("bob.aaaaaaaa")
        payload = self.run_hook(AGENT_ID="pinned.aaaaaaaa")
        self.assertIn("from $AGENT_ID", payload["systemMessage"])
        self.assertIn("ANTROZOUS LISTENER", self.context_of(payload))

    def test_corrupt_flag_does_not_break_session_start(self):
        with open(self.path(), "w") as f:
            f.write("{not json")
        payload = self.run_hook(AGENT_ID="")
        self.assertIn("systemMessage", payload)
        self.assertNotIn("ANTROZOUS LISTENER", self.context_of(payload))


if __name__ == "__main__":
    unittest.main()
