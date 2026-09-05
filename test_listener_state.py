import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts"))

import bootstrap_identity
import identity
import listener_state

SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "scripts", "listener_state.py"
)
HOOK = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "scripts", "bootstrap_identity.py"
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


class WantsListenerTests(ListenerStateTest):
    """`wants_listener` is the tri-state the SessionStart hook actually asks."""

    def test_wants_listener_by_default_when_no_file(self):
        self.assertTrue(listener_state.wants_listener())

    def test_wants_listener_after_explicit_on(self):
        listener_state.set_listening("bob.aaaaaaaa")
        self.assertTrue(listener_state.wants_listener())

    def test_does_not_want_listener_after_explicit_off(self):
        listener_state.clear_listening()
        self.assertFalse(listener_state.wants_listener())

    def test_corrupt_file_falls_back_to_the_default(self):
        with open(self.path(), "w") as f:
            f.write("{not json")
        self.assertTrue(listener_state.wants_listener())


class HostileFileTests(ListenerStateTest):
    """A flag file we cannot parse must not decide whether the user is reachable.

    Under a default of ON, "fall back to the default" and "go dark" are opposite
    outcomes, so every unreadable shape has to land on the default deliberately.
    """

    def setUp(self):
        super().setUp()
        if os.geteuid() == 0:
            self.skipTest("running as root defeats permission-based tests")

    def test_unreadable_file_falls_back_to_the_default(self):
        with open(self.path(), "w") as f:
            json.dump({"listening": False}, f)
        os.chmod(self.path(), 0o000)
        self.addCleanup(os.chmod, self.path(), 0o600)
        self.assertTrue(listener_state.wants_listener())

    def test_binary_file_falls_back_to_the_default(self):
        with open(self.path(), "wb") as f:
            f.write(b"\xff\xfe\x00garbage")
        self.assertTrue(listener_state.wants_listener())

    def test_directory_in_place_of_the_flag_falls_back_to_the_default(self):
        os.makedirs(self.path())
        self.assertTrue(listener_state.wants_listener())

    def test_status_survives_an_unreadable_flag(self):
        with open(self.path(), "w") as f:
            json.dump({"listening": False}, f)
        os.chmod(self.path(), 0o000)
        self.addCleanup(os.chmod, self.path(), 0o600)
        result = self.run_cli("status")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["wants_listener"])

    def test_hook_survives_an_unreadable_flag(self):
        with open(self.path(), "w") as f:
            json.dump({"listening": False}, f)
        os.chmod(self.path(), 0o000)
        self.addCleanup(os.chmod, self.path(), 0o600)
        result = subprocess.run(
            [sys.executable, HOOK],
            capture_output=True,
            text=True,
            env=dict(os.environ, ANTROZOUS_HOME=self.home, USER="testuser"),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertIn("ON BY DEFAULT", (payload.get("hookSpecificOutput") or {}).get(
            "additionalContext", ""
        ))


class NonObjectJsonTests(ListenerStateTest):
    """Valid JSON that is not an object still has to answer every accessor."""

    def write(self, raw):
        with open(self.path(), "w") as f:
            f.write(raw)

    def test_top_level_list_falls_back_to_the_default(self):
        self.write("[1, 2, 3]")
        self.assertTrue(listener_state.wants_listener())
        self.assertFalse(listener_state.is_listening())
        self.assertEqual(listener_state.preference_source(), "default")

    def test_top_level_string_falls_back_to_the_default(self):
        self.write('"listening"')
        self.assertTrue(listener_state.wants_listener())
        self.assertFalse(listener_state.is_listening())

    def test_status_survives_a_non_object_flag(self):
        self.write("[1, 2, 3]")
        result = self.run_cli("status")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["wants_listener"])


class MissingHomeTests(ListenerStateTest):
    """~/.antrozous may not exist yet on a first run."""

    def setUp(self):
        super().setUp()
        os.rmdir(self.home)

    def test_wants_listener_when_home_does_not_exist(self):
        self.assertTrue(listener_state.wants_listener())

    def test_on_creates_the_home_directory(self):
        self.assertEqual(self.run_cli("on", "bob.aaaaaaaa").returncode, 0)
        self.assertTrue(listener_state.is_listening())

    def test_off_creates_the_home_directory(self):
        self.assertEqual(self.run_cli("off").returncode, 0)
        self.assertFalse(listener_state.wants_listener())


class UnwritableHomeTests(ListenerStateTest):
    """Going offline has to be durable, so a failed write must be loud.

    Deleting the flag used to be a best-effort no-op on failure, which was harmless
    when absence meant "off". Now absence means "arm it", so a silently dropped
    opt-out leaves the user listening while believing they are dark.
    """

    def setUp(self):
        super().setUp()
        if os.geteuid() == 0:
            self.skipTest("running as root defeats permission-based tests")
        os.chmod(self.home, 0o500)
        self.addCleanup(os.chmod, self.home, 0o700)

    def test_clear_reports_failure_instead_of_pretending(self):
        with self.assertRaises(OSError):
            listener_state.clear_listening()

    def test_off_exits_non_zero_when_the_opt_out_cannot_be_stored(self):
        result = self.run_cli("off")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("could not", result.stderr.lower())
        self.assertNotIn("Traceback", result.stderr)

    def test_on_exits_non_zero_when_the_flag_cannot_be_stored(self):
        result = self.run_cli("on", "bob.aaaaaaaa")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("could not", result.stderr.lower())
        self.assertNotIn("Traceback", result.stderr)


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

    def test_off_writes_a_tombstone_rather_than_deleting(self):
        """Absence now means auto-arm, so going offline has to leave a record."""
        listener_state.set_listening("bob.aaaaaaaa")
        listener_state.clear_listening()
        self.assertTrue(os.path.exists(self.path()))
        self.assertIs(listener_state.read_state()["listening"], False)
        self.assertFalse(listener_state.wants_listener())

    def test_on_after_off_rearms(self):
        listener_state.set_listening("bob.aaaaaaaa")
        listener_state.clear_listening()
        listener_state.set_listening("bob.aaaaaaaa")
        self.assertTrue(listener_state.is_listening())
        self.assertTrue(listener_state.wants_listener())

    def test_set_requires_an_agent_id(self):
        with self.assertRaises(ValueError):
            listener_state.set_listening("")


class ConcurrencyTests(ListenerStateTest):
    """Several sessions can start, stop, and read the flag at the same time."""

    def test_parallel_writers_never_leave_an_unparseable_flag(self):
        import threading

        stop = threading.Event()
        seen = []

        def writer(n):
            for _ in range(40):
                if n % 2:
                    listener_state.set_listening("bob.aaaaaaaa")
                else:
                    listener_state.clear_listening()

        def reader():
            while not stop.is_set():
                # Any torn read would surface as a non-dict or a raised exception.
                seen.append(listener_state.read_state())

        readers = [threading.Thread(target=reader) for _ in range(3)]
        for t in readers:
            t.start()
        writers = [threading.Thread(target=writer, args=(n,)) for n in range(6)]
        for t in writers:
            t.start()
        for t in writers:
            t.join()
        stop.set()
        for t in readers:
            t.join()

        self.assertTrue(seen)
        for state in seen:
            self.assertIsInstance(state, dict)
            if state:
                self.assertIn("listening", state)

    def test_last_writer_wins(self):
        for _ in range(5):
            listener_state.set_listening("bob.aaaaaaaa")
            listener_state.clear_listening()
        self.assertFalse(listener_state.wants_listener())
        listener_state.set_listening("bob.aaaaaaaa")
        self.assertTrue(listener_state.wants_listener())


class RoundTripTests(ListenerStateTest):
    """Whatever the sequence, the last command is the one that holds."""

    def test_arbitrary_sequences_end_in_the_last_command(self):
        sequence = ["on", "on", "off", "on", "off", "off", "on", "off"]
        for i, command in enumerate(sequence):
            if command == "on":
                self.run_cli("on", "bob.aaaaaaaa")
            else:
                self.run_cli("off")
            expected = command == "on"
            payload = json.loads(self.run_cli("status").stdout)
            self.assertEqual(payload["wants_listener"], expected, "step %d" % i)
            self.assertEqual(payload["source"], "flag")

    def test_agent_id_survives_an_off_then_on(self):
        self.run_cli("on", "bob.aaaaaaaa")
        self.run_cli("off")
        payload = json.loads(self.run_cli("status").stdout)
        self.assertEqual(payload["agent_id"], "bob.aaaaaaaa")


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

    def test_status_on_clean_home_reports_the_default_source(self):
        payload = json.loads(self.run_cli("status").stdout)
        self.assertEqual(payload["source"], "default")
        self.assertTrue(payload["wants_listener"])

    def test_status_after_on_reports_the_flag_source(self):
        self.run_cli("on", "bob.aaaaaaaa")
        payload = json.loads(self.run_cli("status").stdout)
        self.assertEqual(payload["source"], "flag")
        self.assertTrue(payload["wants_listener"])

    def test_status_after_off_reports_the_flag_source(self):
        self.run_cli("off")
        payload = json.loads(self.run_cli("status").stdout)
        self.assertEqual(payload["source"], "flag")
        self.assertFalse(payload["wants_listener"])

    def test_off_clears(self):
        self.run_cli("on", "bob.aaaaaaaa")
        self.assertEqual(self.run_cli("off").returncode, 0)
        self.assertFalse(json.loads(self.run_cli("status").stdout)["listening"])

    def test_on_without_agent_id_fails_loudly(self):
        result = self.run_cli("on")
        self.assertNotEqual(result.returncode, 0)

    def test_unknown_command_fails_loudly(self):
        self.assertNotEqual(self.run_cli("frobnicate").returncode, 0)


class HookResumeTests(ListenerStateTest):
    """The SessionStart hook is what brings a listener back after a restart."""

    def run_hook(self, **env):
        # Pinned explicitly so a developer's own ANTROZOUS_AUTO_LISTEN cannot
        # silently decide the outcome of these tests.
        base = dict(
            os.environ,
            ANTROZOUS_HOME=self.home,
            USER="testuser",
            ANTROZOUS_AUTO_LISTEN="1",
        )
        base.update(env)
        result = subprocess.run(
            [sys.executable, HOOK],
            capture_output=True,
            text=True,
            env=base,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def context_of(self, payload):
        return (payload.get("hookSpecificOutput") or {}).get("additionalContext", "")

    def test_autostart_directive_when_never_configured(self):
        """No flag file at all is the fresh-install case: come up listening."""
        payload = self.run_hook(AGENT_ID="")
        self.assertIn("listener", payload["systemMessage"].lower())
        self.assertIn("/antrozous:stop", payload["systemMessage"])
        context = self.context_of(payload)
        self.assertIn("ANTROZOUS LISTENER", context)
        self.assertIn("antrozous-inbox", context)
        self.assertIn("ON BY DEFAULT", context)
        # The hook fires before the identity popup resolves, so the directive has
        # to tell the model to check for a declined session rather than assume one.
        self.assertIn("whoami", context)

    def test_no_directive_after_an_explicit_stop(self):
        listener_state.clear_listening()
        payload = self.run_hook(AGENT_ID="")
        self.assertNotIn("listener", payload["systemMessage"].lower())
        self.assertNotIn("ANTROZOUS LISTENER", self.context_of(payload))

    def test_autostart_is_suppressed_by_env(self):
        payload = self.run_hook(AGENT_ID="", ANTROZOUS_AUTO_LISTEN="0")
        self.assertNotIn("ANTROZOUS LISTENER", self.context_of(payload))

    def test_env_suppression_does_not_cancel_an_explicit_arm(self):
        listener_state.set_listening("bob.aaaaaaaa")
        payload = self.run_hook(AGENT_ID="", ANTROZOUS_AUTO_LISTEN="0")
        self.assertIn("ANTROZOUS LISTENER", self.context_of(payload))

    def test_autostart_also_fires_on_the_env_pinned_path(self):
        payload = self.run_hook(AGENT_ID="pinned.aaaaaaaa")
        self.assertIn("from $AGENT_ID", payload["systemMessage"])
        self.assertIn("ON BY DEFAULT", self.context_of(payload))

    def test_resume_directive_when_flag_is_on(self):
        listener_state.set_listening("bob.aaaaaaaa")
        payload = self.run_hook(AGENT_ID="")
        self.assertIn("listener", payload["systemMessage"].lower())
        self.assertIn("bob.aaaaaaaa", payload["systemMessage"])
        context = self.context_of(payload)
        self.assertIn("ANTROZOUS LISTENER", context)
        self.assertIn("antrozous-inbox", context)
        self.assertIn("left their inbox listener ARMED", context)

    def test_resume_also_fires_on_the_env_pinned_path(self):
        listener_state.set_listening("bob.aaaaaaaa")
        payload = self.run_hook(AGENT_ID="pinned.aaaaaaaa")
        self.assertIn("from $AGENT_ID", payload["systemMessage"])
        self.assertIn("ANTROZOUS LISTENER", self.context_of(payload))

    def test_auto_listen_env_parsing(self):
        """Only the recognised off-switches suppress the default."""
        for value, expected in [
            ("0", False),
            ("false", False),
            ("FALSE", False),
            ("no", False),
            ("off", False),
            ("  off  ", False),
            ("1", True),
            ("true", True),
            ("", True),
            ("yes", True),
            ("banana", True),
        ]:
            with self.subTest(value=value):
                payload = self.run_hook(AGENT_ID="", ANTROZOUS_AUTO_LISTEN=value)
                armed = "ANTROZOUS LISTENER" in self.context_of(payload)
                self.assertEqual(armed, expected)

    def test_corrupt_flag_does_not_break_session_start(self):
        with open(self.path(), "w") as f:
            f.write("{not json")
        payload = self.run_hook(AGENT_ID="")
        self.assertIn("systemMessage", payload)
        # Unreadable now falls back to the default, which is on.
        self.assertIn("ON BY DEFAULT", self.context_of(payload))


class HookAnnouncementTests(ListenerStateTest):
    def run_hook(self, **env):
        base = dict(
            os.environ,
            ANTROZOUS_HOME=self.home,
            USER="testuser",
            ANTROZOUS_AUTO_LISTEN="1",
        )
        base.update(env)
        result = subprocess.run(
            [sys.executable, HOOK],
            capture_output=True,
            text=True,
            env=base,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_resumed_session_is_announced_with_its_full_id(self):
        os.makedirs(os.path.join(self.home, "sessions"), exist_ok=True)
        path = os.path.join(self.home, "sessions", "sess-a.json")
        with open(path, "w") as f:
            json.dump({"agent_id": "anish-bot-3.e5ox72jb", "pid": None}, f)
        payload = self.run_hook(AGENT_ID="", CLAUDE_CODE_SESSION_ID="sess-a")
        self.assertIn("anish-bot-3.e5ox72jb", payload["systemMessage"])

    def test_unknown_session_does_not_invent_an_ordinal(self):
        payload = self.run_hook(AGENT_ID="", CLAUDE_CODE_SESSION_ID="sess-new")
        self.assertNotIn("-1.", payload["systemMessage"])

    def context_of(self, payload):
        return (payload.get("hookSpecificOutput") or {}).get("additionalContext", "")

    def _named_account(self):
        identity_json = os.path.join(self.home, "identity.json")
        with open(identity_json, "w") as f:
            json.dump(
                {
                    "agent_id": "anish-bot.e5ox72jb",
                    "account_name": "anish-bot",
                    "fingerprint": "e5ox72jb",
                    "confirmed": True,
                },
                f,
            )

    def test_a_later_run_does_not_announce_a_popup(self):
        """Task 4 deleted the per-session popup. The hook must stop promising it."""
        self._named_account()
        payload = self.run_hook(AGENT_ID="", CLAUDE_CODE_SESSION_ID="sess-new")
        self.assertNotIn("prompt will appear", payload["systemMessage"])

    def test_a_first_run_still_announces_the_popup(self):
        payload = self.run_hook(AGENT_ID="", CLAUDE_CODE_SESSION_ID="sess-new")
        self.assertIn("prompt will appear", payload["systemMessage"])

    def test_a_later_runs_model_directive_does_not_promise_a_popup(self):
        """The half that was missed. Branching only the human-visible
        systemMessage left the MODEL's additionalContext still saying the id "is
        being chosen by a popup the gate raises at startup" and listing "says no
        prompt appeared" as a reason to call set_identity -- which from session two
        onward is the normal state, so the directive actively invited a spurious
        set_identity call. A wrong instruction here produces wrong agent
        behaviour, not just a confused reader."""
        self._named_account()
        context = self.context_of(
            self.run_hook(AGENT_ID="", CLAUDE_CODE_SESSION_ID="sess-new")
        )
        self.assertNotIn("popup the gate raises", context)
        self.assertNotIn("says no prompt appeared", context)
        self.assertIn("NO naming popup appears", context)
        self.assertIn("anish-bot.e5ox72jb", context)

    def test_a_later_runs_model_directive_still_forbids_a_reflex_set_identity(self):
        """Dropping the popup claim must not drop the instruction it carried."""
        self._named_account()
        context = self.context_of(
            self.run_hook(AGENT_ID="", CLAUDE_CODE_SESSION_ID="sess-new")
        )
        self.assertIn("Do NOT call", context)
        self.assertIn("set_identity", context)
        self.assertIn("whoami", context)

    def test_a_first_runs_model_directive_still_announces_the_popup(self):
        """The other branch has to keep saying what is true of a FIRST run."""
        context = self.context_of(
            self.run_hook(AGENT_ID="", CLAUDE_CODE_SESSION_ID="sess-new")
        )
        self.assertIn("popup the gate raises", context)


class SessionLineDirectTests(ListenerStateTest):
    """session_line() called directly, bypassing the hook's own __main__.

    identity.describe() -- pre-existing, unmodified, and unguarded -- reads both
    the project and global identity files unconditionally as the very first
    statement of the hook's __main__. Any corruption severe enough to make
    account_agent_id() raise ALSO makes describe() raise, before session_line() is
    ever reached.

    This docstring used to add that the same scenario run through the real hook
    subprocess "still exits 1 with a traceback out of identity.describe()". A later
    commit added the top-level try/except around the hook's __main__ (see
    HookTopLevelGuardTests) and that stopped being true two commits after it was
    written -- verified: the scenario below, run through the hook subprocess, exits
    0 and emits FALLBACK_ANNOUNCEMENT. The subprocess is therefore covered
    elsewhere; what is isolated and proven HERE is session_line()'s own contract:
    called directly, it must not raise even when the account_agent_id() call it
    makes internally does.
    """

    def setUp(self):
        super().setUp()
        if os.geteuid() == 0:
            self.skipTest("running as root defeats permission-based tests")

    def test_survives_an_unreadable_project_identity_file(self):
        os.makedirs(os.path.join(self.home, "sessions"), exist_ok=True)
        with open(os.path.join(self.home, "sessions", "sess-a.json"), "w") as f:
            json.dump({"agent_id": "anish-bot-3.e5ox72jb", "pid": None}, f)
        with open(os.path.join(self.home, "identity.json"), "w") as f:
            json.dump({"account_name": "anish-bot"}, f)

        project_dir = os.path.join(self._tmp.name, "project")
        os.makedirs(os.path.join(project_dir, ".antrozous"))
        project_identity = os.path.join(project_dir, ".antrozous", "identity.json")
        with open(project_identity, "w") as f:
            json.dump({"not_agent_id": "irrelevant"}, f)
        os.chmod(project_identity, 0o000)
        self.addCleanup(os.chmod, project_identity, 0o600)

        saved = {
            k: os.environ.get(k)
            for k in ("CLAUDE_CODE_SESSION_ID", "CLAUDE_PROJECT_DIR", "AGENT_ID")
        }

        def restore():
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

        self.addCleanup(restore)
        os.environ["CLAUDE_CODE_SESSION_ID"] = "sess-a"
        os.environ["CLAUDE_PROJECT_DIR"] = project_dir
        os.environ.pop("AGENT_ID", None)

        try:
            line = bootstrap_identity.session_line()  # must not raise
        except Exception as e:
            self.fail("session_line() raised %r instead of degrading" % (e,))
        self.assertIsInstance(line, str)


class HookTopLevelGuardTests(ListenerStateTest):
    """A corrupt or unreadable identity file must not crash SessionStart itself.

    identity.describe() is unguarded and is the first statement of __main__, so
    any identity-file corruption/permission failure currently propagates all the
    way out of the process. A crashed SessionStart hook stops the session from
    starting, so __main__ needs its own top-level guard independent of anything
    describe() itself does or does not catch.
    """

    def setUp(self):
        super().setUp()
        if os.geteuid() == 0:
            self.skipTest("running as root defeats permission-based tests")

    def test_unreadable_global_identity_does_not_crash_the_hook(self):
        identity_json = os.path.join(self.home, "identity.json")
        with open(identity_json, "w") as f:
            json.dump({"agent_id": "anish-bot.e5ox72jb", "confirmed": True}, f)
        os.chmod(identity_json, 0o000)
        self.addCleanup(os.chmod, identity_json, 0o600)

        result = subprocess.run(
            [sys.executable, HOOK],
            capture_output=True,
            text=True,
            env=dict(
                os.environ, ANTROZOUS_HOME=self.home, USER="testuser", AGENT_ID=""
            ),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertIn("systemMessage", payload)
        self.assertIn("could not read", payload["systemMessage"].lower())
        # The fallback must not pretend things are fine.
        self.assertNotIn("ready", payload["systemMessage"].lower())


if __name__ == "__main__":
    unittest.main()
