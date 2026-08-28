import contextlib
import json
import os
import subprocess
import tempfile
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


class IsolatedIdentityTest(unittest.TestCase):
    """Base for tests that resolve identity.

    Identity now falls back to a GLOBAL file in the user's home, so every test must
    redirect ANTROZOUS_HOME at a temp dir. Without this a test run would read — and
    on a clean machine create — the developer's real ~/.antrozous/identity.json.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = os.path.join(self._tmp.name, "home")
        self.project = os.path.join(self._tmp.name, "project")
        os.makedirs(self.home)
        os.makedirs(self.project)
        self._env = _env(ANTROZOUS_HOME=self.home, AGENT_ID=None, USER="testuser")
        self._env.__enter__()
        self.addCleanup(self._tmp.cleanup)
        self.addCleanup(self._env.__exit__, None, None, None)

    def global_record(self):
        with open(os.path.join(self.home, "identity.json")) as f:
            return json.load(f)

    def project_record(self):
        with open(os.path.join(self.project, ".antrozous", "identity.json")) as f:
            return json.load(f)

    def project_file_exists(self):
        return os.path.exists(os.path.join(self.project, ".antrozous", "identity.json"))

    def write_project(self, agent_id, **extra):
        os.makedirs(os.path.join(self.project, ".antrozous"), exist_ok=True)
        record = {"agent_id": agent_id, "created_at": "2026-01-01"}
        record.update(extra)
        with open(os.path.join(self.project, ".antrozous", "identity.json"), "w") as f:
            json.dump(record, f)


class AgentIdValidationTests(unittest.TestCase):
    def test_accepts_and_lowercases_legal_ids(self):
        self.assertEqual(
            identity.normalize_agent_id("Agent-Shreyaas"), "agent-shreyaas"
        )
        self.assertEqual(identity.normalize_agent_id("  agent-b  "), "agent-b")
        self.assertEqual(identity.normalize_agent_id("a1"), "a1")

    def test_rejects_ids_that_would_break_relay_url_paths(self):
        # These are the ones that matter: agent ids are interpolated into
        # /inbox/<id> and /ws/<id> without escaping.
        for bad in [
            "a/b",
            "../etc",
            "a b",
            "a%2f",
            "agent#1",
            "",
            "x",
            "-lead",
            "trail-",
            "a" * 65,
            None,
            42,
        ]:
            self.assertIsNone(identity.normalize_agent_id(bad), repr(bad))


class SuggestedIdTests(unittest.TestCase):
    def test_global_suggestion_names_the_user(self):
        with _env(USER="shreyaas"):
            self.assertEqual(
                identity.suggest_agent_id(scope="global"), "agent-shreyaas"
            )

    def test_global_suggestion_survives_a_missing_user(self):
        with _env(USER=None, LOGNAME=None):
            suggested = identity.suggest_agent_id(scope="global")
            self.assertIsNotNone(identity.normalize_agent_id(suggested), suggested)

    def test_project_suggestion_carries_the_directory_name(self):
        with tempfile.TemporaryDirectory() as root:
            project = os.path.join(root, "my-backend")
            os.makedirs(project)

            suggested = identity.suggest_agent_id(project, scope="project")

            self.assertTrue(suggested.startswith("agent-my-backend-"), suggested)
            self.assertIsNotNone(identity.normalize_agent_id(suggested))

    def test_project_suggestion_survives_an_unslugifiable_directory(self):
        with tempfile.TemporaryDirectory() as root:
            project = os.path.join(root, "!!!")
            os.makedirs(project)
            suggested = identity.suggest_agent_id(project, scope="project")
            self.assertIsNotNone(identity.normalize_agent_id(suggested), suggested)

    def test_same_directory_name_does_not_collide(self):
        with tempfile.TemporaryDirectory() as root:
            a, b = os.path.join(root, "one", "api"), os.path.join(root, "two", "api")
            os.makedirs(a)
            os.makedirs(b)
            # Global namespace on the relay: a collision silently merges inboxes.
            self.assertNotEqual(
                identity.suggest_agent_id(a, scope="project"),
                identity.suggest_agent_id(b, scope="project"),
            )


class ResolutionTierTests(IsolatedIdentityTest):
    """env > project > global > generate."""

    def test_generation_writes_the_global_file_not_the_project(self):
        agent_id = identity.resolve_agent_id(self.project)

        self.assertEqual(self.global_record()["agent_id"], agent_id)
        self.assertFalse(
            self.project_file_exists(), "generation must not create a project identity"
        )

    def test_global_identity_is_shared_across_directories(self):
        # The whole point of the global tier: same agent from anywhere.
        first = identity.resolve_agent_id(self.project)
        other = os.path.join(self._tmp.name, "somewhere-else")
        os.makedirs(other)

        self.assertEqual(identity.resolve_agent_id(other), first)

    def test_project_file_overrides_the_global_one(self):
        identity.resolve_agent_id(self.project)
        self.write_project("agent-project-scoped")

        self.assertEqual(
            identity.resolve_agent_id(self.project), "agent-project-scoped"
        )

    def test_env_overrides_everything(self):
        self.write_project("agent-project-scoped")
        with _env(AGENT_ID="agent-from-env"):
            self.assertEqual(identity.resolve_agent_id(self.project), "agent-from-env")

    def test_resolution_is_stable_across_calls(self):
        first = identity.resolve_agent_id(self.project)
        self.assertEqual(identity.resolve_agent_id(self.project), first)


class SetAgentIdTests(IsolatedIdentityTest):
    def test_global_scope_is_the_default_and_applies_everywhere(self):
        returned = identity.set_agent_id(self.project, "Agent-Renamed")

        self.assertEqual(returned, "agent-renamed")
        self.assertEqual(self.global_record()["agent_id"], "agent-renamed")
        other = os.path.join(self._tmp.name, "elsewhere")
        os.makedirs(other)
        self.assertEqual(identity.resolve_agent_id(other), "agent-renamed")

    def test_project_scope_writes_only_that_directory(self):
        identity.set_agent_id(self.project, "agent-global-one")

        identity.set_agent_id(self.project, "agent-just-here", scope="project")

        self.assertEqual(self.project_record()["agent_id"], "agent-just-here")
        self.assertEqual(self.global_record()["agent_id"], "agent-global-one")
        self.assertEqual(identity.resolve_agent_id(self.project), "agent-just-here")

    def test_global_write_alone_stays_shadowed_by_a_project_file(self):
        # Documents the trap the gate has to disclose: the write succeeds and
        # resolution is unchanged, so a rename looks like it did nothing.
        self.write_project("agent-project-scoped")

        identity.set_agent_id(self.project, "agent-new-global")

        self.assertEqual(self.global_record()["agent_id"], "agent-new-global")
        self.assertEqual(
            identity.resolve_agent_id(self.project), "agent-project-scoped"
        )

    def test_dropping_the_override_consolidates_onto_the_global_id(self):
        self.write_project("agent-project-scoped")

        identity.set_agent_id(
            self.project, "agent-new-global", drop_project_override=True
        )

        self.assertFalse(self.project_file_exists())
        self.assertEqual(identity.resolve_agent_id(self.project), "agent-new-global")

    def test_consolidation_keeps_the_replaced_id_in_provenance(self):
        self.write_project("agent-was-project")

        identity.set_agent_id(
            self.project, "agent-now-global", drop_project_override=True
        )

        self.assertEqual(self.global_record()["previous_agent_id"], "agent-was-project")

    def test_rename_preserves_creation_time(self):
        identity.resolve_agent_id(self.project)
        created_at = self.global_record()["created_at"]

        identity.set_agent_id(self.project, "agent-second")

        record = self.global_record()
        self.assertEqual(record["created_at"], created_at)
        self.assertIn("renamed_at", record)

    def test_invalid_id_raises_and_changes_nothing(self):
        original = identity.resolve_agent_id(self.project)

        for scope in ("global", "project"):
            with self.assertRaises(ValueError):
                identity.set_agent_id(self.project, "bad/id", scope=scope)

        self.assertEqual(identity.resolve_agent_id(self.project), original)
        self.assertFalse(self.project_file_exists())

    def test_works_before_any_identity_exists(self):
        self.assertEqual(
            identity.set_agent_id(self.project, "agent-fresh"), "agent-fresh"
        )
        self.assertEqual(identity.resolve_agent_id(self.project), "agent-fresh")


class DescribeTests(IsolatedIdentityTest):
    def test_reports_generated_then_global(self):
        info = identity.describe(self.project)
        self.assertEqual(info["source"], "generated")
        self.assertEqual(info["path"], os.path.join(self.home, "identity.json"))

        # Same id on the next call, now sourced from the saved global file.
        again = identity.describe(self.project)
        self.assertEqual(again["source"], "global")
        self.assertEqual(again["agent_id"], info["agent_id"])

    def test_reports_project_source_and_names_the_shadowed_global(self):
        identity.set_agent_id(self.project, "agent-global-one")
        self.write_project("agent-project-scoped")

        info = identity.describe(self.project)

        self.assertEqual(info["agent_id"], "agent-project-scoped")
        self.assertEqual(info["source"], "project")
        self.assertEqual(info["shadowed"], "agent-global-one")

    def test_env_override_is_reported_and_names_the_shadowed_id(self):
        # The exact confusion this exists to prevent: a set_identity that writes
        # correctly while the session keeps using an unrelated env value.
        identity.set_agent_id(self.project, "agent-saved")

        with _env(AGENT_ID="agent-from-env"):
            info = identity.describe(self.project)

        self.assertEqual(info["agent_id"], "agent-from-env")
        self.assertEqual(info["source"], "env")
        self.assertEqual(info["shadowed"], "agent-saved")
        self.assertIsNone(info["path"])

    def test_always_reports_both_candidate_paths(self):
        info = identity.describe(self.project)
        self.assertEqual(info["global_path"], os.path.join(self.home, "identity.json"))
        self.assertEqual(
            info["project_path"],
            os.path.join(self.project, ".antrozous", "identity.json"),
        )


class SetupPromptTests(IsolatedIdentityTest):
    """The session-start prompt must fire once and then stay quiet."""

    def test_generated_identity_needs_setup(self):
        self.assertTrue(identity.describe(self.project)["needs_setup"])
        # Still pending next session — a dismissed prompt must reappear.
        self.assertTrue(identity.describe(self.project)["needs_setup"])

    def test_rename_clears_the_prompt(self):
        identity.resolve_agent_id(self.project)

        identity.set_agent_id(self.project, "agent-named")

        self.assertFalse(identity.describe(self.project)["needs_setup"])

    def test_mark_confirmed_keeps_the_id_and_clears_the_prompt(self):
        original = identity.resolve_agent_id(self.project)

        returned = identity.mark_confirmed(self.project)

        self.assertEqual(returned, original)
        self.assertEqual(identity.resolve_agent_id(self.project), original)
        self.assertFalse(identity.describe(self.project)["needs_setup"])

    def test_mark_confirmed_targets_the_file_in_force(self):
        # A project override is what the user is actually using, so declining must
        # silence the prompt for THAT id, not for a global one they never see.
        identity.set_agent_id(self.project, "agent-global-one")
        self.write_project("agent-project-scoped")

        identity.mark_confirmed(self.project)

        self.assertTrue(self.project_record()["confirmed"])
        self.assertFalse(identity.describe(self.project)["needs_setup"])

    def test_mark_confirmed_is_idempotent(self):
        identity.resolve_agent_id(self.project)
        identity.mark_confirmed(self.project)
        self.assertIsNotNone(identity.mark_confirmed(self.project))
        self.assertFalse(identity.describe(self.project)["needs_setup"])

    def test_mark_confirmed_with_nothing_saved_is_a_noop(self):
        self.assertIsNone(identity.mark_confirmed(self.project))

    def test_identity_predating_the_flag_is_prompted_once(self):
        # Files written before 'confirmed' existed must get the naming prompt, not
        # be treated as already decided.
        self.write_project("agent-legacy")

        info = identity.describe(self.project)

        self.assertEqual(info["agent_id"], "agent-legacy")
        self.assertTrue(info["needs_setup"])

    def test_env_identity_is_never_prompted(self):
        # An env id can't be changed by writing a file, so prompting is pointless.
        with _env(AGENT_ID="agent-env"):
            self.assertFalse(identity.describe(self.project)["needs_setup"])


class QualifiedIdTests(unittest.TestCase):
    """Ids are "<name>.<fingerprint>" so two people sharing a name stay distinct."""

    def test_compose_and_split_roundtrip(self):
        self.assertEqual(identity.compose_agent_id("Babu", "27uumo4l"), "babu.27uumo4l")
        self.assertEqual(identity.split_agent_id("babu.27uumo4l"), ("babu", "27uumo4l"))
        self.assertTrue(identity.is_qualified("babu.27uumo4l"))

    def test_legacy_unqualified_ids_still_parse(self):
        for legacy in ("agent-9210a9a2e7", "agent-shreyaas", "babu"):
            self.assertEqual(identity.split_agent_id(legacy), (legacy, None))
            self.assertFalse(identity.is_qualified(legacy))
            self.assertEqual(identity.agent_name(legacy), legacy)

    def test_a_dotted_suffix_that_is_not_a_fingerprint_is_not_split(self):
        # Wrong length, and characters outside base32 must not be read as a
        # fingerprint, or a name containing a dot would silently lose its tail.
        for weird in ("foo.bar", "foo.abc", "foo.ABCDEFGH", "foo.abcdef19"):
            self.assertEqual(identity.split_agent_id(weird), (weird, None))

    def test_compose_without_a_fingerprint_returns_the_bare_name(self):
        self.assertEqual(identity.compose_agent_id("babu", None), "babu")
        self.assertEqual(identity.compose_agent_id("babu", "TOO-SHORT"), "babu")

    def test_compose_rejects_an_illegal_name(self):
        for bad in ("a/b", "", "-x", "x-", "a" * 40, None):
            self.assertIsNone(identity.compose_agent_id(bad, "27uumo4l"), repr(bad))

    def test_name_normalization_drops_an_existing_fingerprint(self):
        # Re-typing a full id where a name is expected must not double the suffix.
        self.assertEqual(identity.normalize_name("Babu.27uumo4l"), "babu")

    def test_qualified_ids_are_legal_agent_ids(self):
        composed = identity.compose_agent_id("babu", "27uumo4l")
        self.assertIsNotNone(identity.normalize_agent_id(composed))

    def test_same_name_different_fingerprints_do_not_collide(self):
        self.assertNotEqual(
            identity.compose_agent_id("shreyaas", "aaaaaaaa"),
            identity.compose_agent_id("shreyaas", "bbbbbbbb"),
        )


class FingerprintCacheTests(IsolatedIdentityTest):
    """The gate computes the fingerprint; crypto-free callers read it back."""

    def test_save_and_read(self):
        self.assertEqual(identity.save_fingerprint("27uumo4l"), "27uumo4l")
        self.assertEqual(identity.saved_fingerprint(), "27uumo4l")

    def test_illegal_fingerprints_are_refused(self):
        for bad in ("", "SHORT", "abcdefg1", "not-base32!", None, 7):
            self.assertIsNone(identity.save_fingerprint(bad), repr(bad))
        self.assertIsNone(identity.saved_fingerprint())

    def test_rename_preserves_the_cached_fingerprint(self):
        # Regression: set_agent_id rebuilt the record and dropped the fingerprint,
        # leaving the hook unable to build a qualified id.
        identity.save_fingerprint("27uumo4l")

        identity.set_agent_id(self.project, "babu.27uumo4l")

        self.assertEqual(identity.saved_fingerprint(), "27uumo4l")

    def test_mark_confirmed_preserves_the_cached_fingerprint(self):
        identity.save_fingerprint("27uumo4l")
        identity.resolve_agent_id(self.project)

        identity.mark_confirmed(self.project)

        self.assertEqual(identity.saved_fingerprint(), "27uumo4l")

    def test_suggestion_qualifies_a_legacy_id_from_the_cache(self):
        identity.save_fingerprint("27uumo4l")
        identity.set_agent_id(self.project, "agent-legacy")

        self.assertEqual(
            identity.suggest_session_id("agent-legacy"), "agent-legacy.27uumo4l"
        )


class SessionRegistryTests(IsolatedIdentityTest):
    """Per-session ids: each tab registers so the next one is offered a free name."""

    def _fake_session(self, pid, agent_id):
        os.makedirs(identity.sessions_dir(), exist_ok=True)
        with open(os.path.join(identity.sessions_dir(), "%d.json" % pid), "w") as f:
            json.dump({"agent_id": agent_id, "pid": pid}, f)

    def test_register_then_unregister(self):
        identity.register_session("agent-tab-one")

        self.assertEqual(identity.live_sessions().get(os.getpid()), "agent-tab-one")

        identity.unregister_session()
        self.assertNotIn(os.getpid(), identity.live_sessions())

    def test_unregister_without_registering_is_a_noop(self):
        identity.unregister_session()

    def test_dead_sessions_are_excluded_but_not_deleted(self):
        # A very high pid is almost certainly free. Records are never garbage
        # collected — the record has to survive so a resumed session can find it.
        self._fake_session(999999, "agent-ghost")

        self.assertNotIn(999999, identity.live_sessions())
        self.assertIn("999999.json", os.listdir(identity.sessions_dir()))

    def test_malformed_session_files_are_ignored(self):
        os.makedirs(identity.sessions_dir(), exist_ok=True)
        for name, body in (
            ("notapid.json", "{}"),
            ("readme.txt", "x"),
            ("7.json", "{"),
        ):
            with open(os.path.join(identity.sessions_dir(), name), "w") as f:
                f.write(body)

        identity.live_sessions()

    def test_suggestion_is_the_base_when_nothing_is_running(self):
        self.assertEqual(
            identity.suggest_session_id("agent-shreyaas"), "agent-shreyaas"
        )

    def test_suggestion_avoids_live_ids(self):
        identity.register_session("agent-shreyaas")

        self.assertEqual(
            identity.suggest_session_id("agent-shreyaas"), "agent-shreyaas-2"
        )

    def test_suggestion_walks_past_several_live_ids(self):
        identity.register_session("agent-shreyaas")
        self._fake_session(os.getppid(), "agent-shreyaas-2")

        self.assertEqual(
            identity.suggest_session_id("agent-shreyaas"), "agent-shreyaas-3"
        )

    def test_suggestion_stays_legal_for_a_long_base(self):
        base = "a" * 63
        identity.register_session(base)

        suggested = identity.suggest_session_id(base)

        self.assertIsNotNone(identity.normalize_agent_id(suggested), suggested)

    def test_live_sessions_is_empty_when_the_dir_is_missing(self):
        self.assertEqual(identity.live_sessions(), {})

    def test_sessions_live_under_the_overridable_home(self):
        self.assertTrue(identity.sessions_dir().startswith(self.home))


class SessionKeyTests(IsolatedIdentityTest):
    """Records are keyed by the Claude session so --resume reclaims its queue."""

    def test_session_key_comes_from_the_claude_session_id(self):
        with _env(CLAUDE_CODE_SESSION_ID="a133d3ce-293b-4c3a-9a83-5d5ec88a51ef"):
            self.assertEqual(
                identity.current_session_key(),
                "a133d3ce-293b-4c3a-9a83-5d5ec88a51ef",
            )

    def test_session_key_falls_back_to_the_pid_outside_claude_code(self):
        with _env(CLAUDE_CODE_SESSION_ID=None):
            self.assertEqual(identity.current_session_key(), "pid-%d" % os.getpid())

    def test_a_hostile_session_id_is_not_used_as_a_filename(self):
        with _env(CLAUDE_CODE_SESSION_ID="../../etc/passwd"):
            self.assertEqual(identity.current_session_key(), "pid-%d" % os.getpid())

    def test_record_is_written_under_the_session_key(self):
        with _env(CLAUDE_CODE_SESSION_ID="sess-one"):
            identity.register_session("bob.aaaaaaaa")
            self.assertTrue(
                os.path.exists(os.path.join(identity.sessions_dir(), "sess-one.json"))
            )

    def test_same_session_key_different_pid_reuses_the_record(self):
        """This is what makes --resume keep its address."""
        with _env(CLAUDE_CODE_SESSION_ID="sess-one"):
            identity.register_session("bob.aaaaaaaa")
            identity.unregister_session()
            record = identity.session_records()["sess-one"]
        self.assertEqual(record["agent_id"], "bob.aaaaaaaa")
        self.assertIsNone(record["pid"])

    def test_unregister_keeps_the_record_but_marks_it_not_live(self):
        with _env(CLAUDE_CODE_SESSION_ID="sess-one"):
            identity.register_session("bob.aaaaaaaa")
            identity.unregister_session()
            self.assertIn("sess-one", identity.session_records())
            self.assertNotIn("sess-one", identity.live_session_records())

    def test_records_are_never_pruned(self):
        os.makedirs(identity.sessions_dir(), exist_ok=True)
        with open(os.path.join(identity.sessions_dir(), "ghost.json"), "w") as f:
            json.dump({"agent_id": "ghost.aaaaaaaa", "pid": 999999}, f)
        self.assertIn("ghost", identity.session_records())
        self.assertNotIn("ghost", identity.live_session_records())
        self.assertTrue(
            os.path.exists(os.path.join(identity.sessions_dir(), "ghost.json"))
        )

    def test_live_sessions_still_returns_pid_to_agent_id(self):
        with _env(CLAUDE_CODE_SESSION_ID="sess-one"):
            identity.register_session("bob.aaaaaaaa")
        self.assertEqual(identity.live_sessions().get(os.getpid()), "bob.aaaaaaaa")

    def test_one_unreadable_record_does_not_break_the_registry(self):
        """Spec section 12. identity._read_json only catches a missing file and bad
        JSON, so a permission error, a directory, or non-UTF-8 bytes would take the
        whole registry down with it."""
        if os.geteuid() == 0:
            self.skipTest("running as root defeats permission-based tests")
        os.makedirs(identity.sessions_dir(), exist_ok=True)
        good = os.path.join(identity.sessions_dir(), "good.json")
        with open(good, "w") as f:
            json.dump({"agent_id": "bob.aaaaaaaa", "pid": None}, f)
        bad = os.path.join(identity.sessions_dir(), "bad.json")
        with open(bad, "w") as f:
            f.write("{}")
        os.chmod(bad, 0o000)
        self.addCleanup(os.chmod, bad, 0o600)
        self.assertIn("good", identity.session_records())

    def test_a_non_object_record_is_ignored(self):
        os.makedirs(identity.sessions_dir(), exist_ok=True)
        with open(os.path.join(identity.sessions_dir(), "weird.json"), "w") as f:
            f.write("[1, 2, 3]")
        self.assertNotIn("weird", identity.session_records())


class AccountAddressTests(IsolatedIdentityTest):
    """The account address is stable across sessions; session addresses vary."""

    def test_account_address_qualifies_the_saved_name(self):
        identity.save_fingerprint("27uumo4l")
        identity.set_agent_id(self.project, "shreyaas.27uumo4l")

        self.assertEqual(identity.account_agent_id(self.project), "shreyaas.27uumo4l")

    def test_account_address_is_unchanged_by_session_names(self):
        identity.save_fingerprint("27uumo4l")
        identity.set_agent_id(self.project, "shreyaas.27uumo4l")
        before = identity.account_agent_id(self.project)

        identity.register_session("review.27uumo4l")

        self.assertEqual(identity.account_agent_id(self.project), before)

    def test_account_address_qualifies_a_legacy_saved_id(self):
        identity.save_fingerprint("27uumo4l")
        identity.set_agent_id(self.project, "agent-legacy")

        self.assertEqual(
            identity.account_agent_id(self.project), "agent-legacy.27uumo4l"
        )

    def test_account_address_survives_a_missing_fingerprint(self):
        identity.set_agent_id(self.project, "agent-legacy")
        self.assertEqual(identity.account_agent_id(self.project), "agent-legacy")


class PrimarySessionTests(IsolatedIdentityTest):
    """Exactly one session drains account mail, and the slot is self-healing."""

    def _fake_session(self, pid, agent_id, primary=False):
        os.makedirs(identity.sessions_dir(), exist_ok=True)
        record = {"agent_id": agent_id, "pid": pid}
        if primary:
            record["primary"] = True
        with open(os.path.join(identity.sessions_dir(), "%d.json" % pid), "w") as f:
            json.dump(record, f)

    def test_first_session_claims_the_vacant_slot(self):
        identity.register_session("a.27uumo4l")

        self.assertTrue(identity.claim_primary())
        self.assertTrue(identity.is_primary())
        self.assertEqual(identity.primary_pid(), os.getpid())

    def test_claiming_is_idempotent(self):
        identity.register_session("a.27uumo4l")
        identity.claim_primary()
        self.assertTrue(identity.claim_primary())

    def test_a_second_session_does_not_steal_the_slot(self):
        # A live holder keeps it, so account mail has exactly one reader.
        self._fake_session(os.getppid(), "other.27uumo4l", primary=True)
        identity.register_session("a.27uumo4l")

        self.assertFalse(identity.claim_primary())
        self.assertFalse(identity.is_primary())

    def test_force_hands_the_slot_over(self):
        self._fake_session(os.getppid(), "other.27uumo4l", primary=True)
        identity.register_session("a.27uumo4l")

        self.assertTrue(identity.claim_primary(force=True))
        self.assertEqual(identity.primary_pid(), os.getpid())

    def test_a_dead_holder_frees_the_slot(self):
        # The failure mode of a designated primary: it must not strand account mail
        # when that session exits.
        self._fake_session(999999, "ghost.27uumo4l", primary=True)
        identity.register_session("a.27uumo4l")

        self.assertTrue(identity.claim_primary())
        self.assertTrue(identity.is_primary())

    def test_claiming_without_registering_fails(self):
        self.assertFalse(identity.claim_primary())
        self.assertIsNone(identity.primary_pid())

    def test_registration_preserves_the_primary_flag(self):
        identity.register_session("a.27uumo4l")
        identity.claim_primary()

        identity.register_session("renamed.27uumo4l")

        self.assertTrue(identity.is_primary())

    def test_unregister_releases_the_slot(self):
        identity.register_session("a.27uumo4l")
        identity.claim_primary()

        identity.unregister_session()

        self.assertIsNone(identity.primary_pid())


class GitExclusionTests(unittest.TestCase):
    def test_project_identity_is_locally_git_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = os.path.join(tmp, "repo")
            home = os.path.join(tmp, "home")
            os.makedirs(home)
            subprocess.run(["git", "init", "--quiet", repo], check=True)
            project = os.path.join(repo, "packages", "demo")
            os.makedirs(project)

            with _env(ANTROZOUS_HOME=home, AGENT_ID=None):
                agent_id = identity.set_agent_id(project, "agent-demo", scope="project")

            self.assertEqual(agent_id, "agent-demo")
            self.assertTrue(
                os.path.isfile(os.path.join(project, ".antrozous", "identity.json"))
            )
            status = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=repo,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(status.stdout, "")

            exclude_path = subprocess.run(
                ["git", "rev-parse", "--git-path", "info/exclude"],
                cwd=repo,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            if not os.path.isabs(exclude_path):
                exclude_path = os.path.join(repo, exclude_path)
            with open(exclude_path, encoding="utf-8") as file:
                self.assertIn(".antrozous/", {line.strip() for line in file})

    def test_global_identity_does_not_touch_the_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = os.path.join(tmp, "repo")
            home = os.path.join(tmp, "home")
            os.makedirs(home)
            subprocess.run(["git", "init", "--quiet", repo], check=True)

            with _env(ANTROZOUS_HOME=home, AGENT_ID=None):
                identity.resolve_agent_id(repo)

            self.assertFalse(os.path.exists(os.path.join(repo, ".antrozous")))
            status = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=repo,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(status.stdout, "")


if __name__ == "__main__":
    unittest.main()
