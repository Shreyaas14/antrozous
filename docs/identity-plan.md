# Identity and Session Addressing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give each Claude session a stable, derived address of the form
`<account>-<n>.<fingerprint>` that survives `claude --resume`, and make one account
name — chosen once — the only thing a user is ever asked to pick.

**Architecture:** Session identity moves from being keyed by OS pid to being keyed
by `CLAUDE_CODE_SESSION_ID`, so a record outlives its process and a resumed session
reclaims its own queue. Ordinals come from a monotonic counter in
`~/.antrozous/identity.json` and are never reused. The account address stays a real
inbox — the "front door" for anyone who addresses you by your public alias — drained
by exactly one live session (the primary), which is a one-line fix to
`inbox_addresses()` rather than new machinery.

**Tech Stack:** Python 3 standard library only. `unittest` for tests. No new
dependencies, no relay changes.

**Spec:** `docs/identity-design.md`

## Global Constraints

- **Separator is a hyphen, never a dot.** `anish-bot.1.e5ox72jb` fails the relay's
  `_QUALIFIED_ID_RE` (`src/antrozous/server.py:97`), which gates `_check_signature`,
  `publish_keys`, `get_keys` and `list_inboxes`, and `normalize_name` truncates at
  the first dot client-side so the ordinal is silently dropped.
- **Session name grammar:** `NAME_RE = ^[a-z0-9][a-z0-9_-]{0,31}[a-z0-9]$` — 2 to 33
  characters. `<account>-<n>` must fit inside that; see Task 3.
- **Fingerprint grammar:** `FINGERPRINT_RE = ^[a-z2-7]{8}$`.
- **Session records are never garbage-collected.** No TTL, no pruning, no deleter.
- **No relay changes in this plan.** `src/antrozous/server.py` is not modified.
- **Tests redirect `ANTROZOUS_HOME` at a temp dir** — never touch the developer's
  real `~/.antrozous`. Follow `IsolatedIdentityTest` in `test_identity.py:30`.
- **Run tests with** `python3 -m unittest <module> -v` from the repo root. The full
  suite is `python3 -m unittest discover -s . -p 'test_*.py'`; `test_auth.py` fails
  to import (`fastapi` missing) on a clean tree and is a pre-existing, unrelated
  failure.

---

## File Structure

| File | Responsibility | Tasks |
|---|---|---|
| `identity.py` | session keying, account name, ordinal counter, id derivation, primary | 1, 2, 3, 6 |
| `mcp_gate.py` | startup flow, whoami, set_identity, inbox addresses | 4, 6, 7, 8, 9 |
| `scripts/bootstrap_identity.py` | SessionStart announcement | 5 |
| `test_identity.py` | unit tests for `identity.py` | 1, 2, 3, 6 |
| `test_session_rename.py` | gate-level startup and rename tests | 4, 8, 9 |
| `test_listener_state.py` | hook subprocess tests | 5 |
| `skills/antrozous-inbox/SKILL.md`, `README.md`, `docs/encryption-design.md` | docs truth-up | 10 |

---

## Task 0: Verify the resume assumption (BLOCKING)

Section 13 of the spec is blocking. Everything from Task 1 onward assumes
`CLAUDE_CODE_SESSION_ID` reaches the gate and survives `claude --resume`. **Do not
start Task 1 until this passes.**

**Files:**
- Modify (temporarily): `mcp_gate.py` — the top of `main()`

- [ ] **Step 1: Add a temporary probe**

In `mcp_gate.py`, at the very top of `main()` (currently `log("starting as ...")`),
add:

```python
    # TEMPORARY probe for docs/identity-plan.md Task 0. Remove before Task 1.
    try:
        probe = os.path.join(identity.global_dir(), "session-probe.log")
        os.makedirs(identity.global_dir(), exist_ok=True)
        with open(probe, "a") as f:
            f.write(
                "%s pid=%d session=%s\n"
                % (
                    datetime.now(),
                    os.getpid(),
                    os.environ.get("CLAUDE_CODE_SESSION_ID", "<ABSENT>"),
                )
            )
    except OSError:
        pass
```

If `datetime` is not already imported in `mcp_gate.py`, use `time.time()` instead.

- [ ] **Step 2: Start a session and record the id**

```bash
cd /Users/anishrane && claude --plugin-dir ./antrozous
```

Type anything, then exit. Then:

```bash
cat ~/.antrozous/session-probe.log
```

Expected: one line with a UUID, not `<ABSENT>`. **If it says `<ABSENT>`, the gate
does not inherit the variable** — stop and report; the fallback in spec §13 applies
and Task 1 must key on `pid-<pid>` only.

- [ ] **Step 3: Resume that session and compare**

```bash
cd /Users/anishrane && claude --resume
```

Pick the session from step 2. Exit, then:

```bash
cat ~/.antrozous/session-probe.log
```

Expected: a second line with a **different pid** and the **same session UUID**.

- [ ] **Step 4: Record the outcome and revert the probe**

Write the result into `docs/identity-design.md` §13, replacing "Open verification —
blocking" with the observed answer and the date. Then remove the probe block from
`mcp_gate.py` and delete `~/.antrozous/session-probe.log`.

- [ ] **Step 5: Commit**

```bash
git add docs/identity-design.md
git commit -m "docs: record the outcome of the resume-stability check"
```

---

## Task 1: Key session records by Claude session, not pid

**Files:**
- Modify: `identity.py:70-72` (`_session_path`), `identity.py:86-176`
  (`session_records`, `live_sessions`, `register_session`, `primary_pid`,
  `claim_primary`, `is_primary`, `unregister_session`)
- Test: `test_identity.py` (extend `SessionRegistryTests` at line 435)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `identity.current_session_key() -> str` — the record filename stem.
  - `identity.session_records() -> dict[str, dict]` — **all** records, keyed by
    session key, no pruning.
  - `identity.live_session_records() -> dict[str, dict]` — records whose stored
    `pid` is alive.
  - `identity.live_sessions() -> dict[int, str]` — **unchanged signature**,
    `{pid: agent_id}` for live sessions only. Existing callers in `mcp_gate.py` and
    `scripts/bootstrap_identity.py` keep working untouched.
  - `identity.register_session(agent_id, primary=False) -> str` — unchanged
    signature, now writes `sessions/<session-key>.json` with `pid` inside.
  - `identity.unregister_session() -> None` — unchanged signature, now sets
    `pid: None` instead of deleting the file.

- [ ] **Step 1: Write the failing tests**

Add to `test_identity.py`:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest test_identity.SessionKeyTests -v`
Expected: FAIL — `AttributeError: module 'identity' has no attribute 'current_session_key'`

- [ ] **Step 3: Implement**

In `identity.py`, add near the other regexes at the top:

```python
# A session key becomes a filename, so it is restricted to characters that cannot
# escape the sessions directory. Claude Code's session id is a UUID and fits.
SESSION_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
```

Replace `_session_path` and rewrite the registry block:

```python
def current_session_key():
    """Filename stem for this session's record.

    Keyed by the CLAUDE SESSION rather than the pid so that `claude --resume` in a
    fresh terminal comes back as the same agent, polling the same queue. Falls back
    to the pid outside Claude Code (tests, direct invocation), where there is no
    session to be stable across.
    """
    raw = (os.environ.get("CLAUDE_CODE_SESSION_ID") or "").strip()
    if raw and SESSION_KEY_RE.match(raw) and ".." not in raw:
        return raw
    return "pid-%d" % os.getpid()


def _session_path(key=None):
    return os.path.join(sessions_dir(), "%s.json" % (key or current_session_key()))


def session_records():
    """{session_key: record} for EVERY record on disk.

    Nothing is pruned. A record outlives its process on purpose — the session may
    resume — and they are a few hundred bytes each, so accumulation is cheaper than
    guessing when a session has been abandoned.
    """
    out = {}
    try:
        names = os.listdir(sessions_dir())
    except OSError:
        return out
    for name in names:
        if not name.endswith(".json"):
            continue
        try:
            data = _read_json(os.path.join(sessions_dir(), name))
        except (OSError, ValueError):
            # _read_json only catches a missing file and bad JSON. A permission
            # error, a directory in a record's place, or non-UTF-8 bytes would
            # otherwise take the whole registry down over one bad file.
            continue
        if isinstance(data, dict) and data.get("agent_id"):
            out[name[:-5]] = data
    return out


def live_session_records():
    """{session_key: record} for records whose process is still running."""
    return {
        key: rec
        for key, rec in session_records().items()
        if isinstance(rec.get("pid"), int) and _pid_alive(rec["pid"])
    }


def live_sessions():
    """{pid: agent_id} for sessions still running.

    Signature deliberately unchanged: whoami, the startup prompt and the SessionStart
    hook all render peers as (pid, agent_id) pairs.
    """
    return {rec["pid"]: rec["agent_id"] for rec in live_session_records().values()}


def register_session(agent_id, primary=False):
    os.makedirs(sessions_dir(), exist_ok=True)
    record = _read_json(_session_path()) or {}
    record.update(
        {
            "claude_session_id": current_session_key(),
            "agent_id": agent_id,
            "pid": os.getpid(),
            "started_at": record.get("started_at") or str(datetime.now()),
            "last_seen_at": str(datetime.now()),
        }
    )
    if primary:
        record["primary"] = True
    _write_json(_session_path(), record)
    return agent_id


def unregister_session():
    """Mark this session not-live WITHOUT deleting its record.

    The record has to survive so a resumed session finds its own address. Clearing
    the pid rather than leaving it stale matters: pids are recycled by the OS, and a
    stale one would eventually make a dead record look alive.
    """
    record = _read_json(_session_path())
    if not record:
        return
    record["pid"] = None
    record.pop("primary", None)
    record["last_seen_at"] = str(datetime.now())
    try:
        _write_json(_session_path(), record)
    except OSError:
        pass
```

Rewrite `primary_pid` / `claim_primary` to work over live records:

```python
def primary_pid():
    for rec in live_session_records().values():
        if rec.get("primary"):
            return rec["pid"]
    return None


def claim_primary(force=False):
    """Take the primary slot if it is vacant or held by a dead session.

    Claimed opportunistically rather than assigned once, so a closed primary does not
    strand front-door mail — the next session to look takes over.
    """
    holder = primary_pid()
    if holder == os.getpid():
        return True
    if holder is not None and not force:
        return False
    if holder is not None:
        for key, rec in live_session_records().items():
            if rec.get("primary"):
                rec.pop("primary", None)
                try:
                    _write_json(_session_path(key), rec)
                except OSError:
                    return False
    record = _read_json(_session_path())
    if not (record and record.get("agent_id")):
        return False
    record["primary"] = True
    _write_json(_session_path(), record)
    return True
```

`is_primary()` is unchanged (`primary_pid() == os.getpid()`).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m unittest test_identity -v`
Expected: PASS, including the pre-existing `SessionRegistryTests` and
`PrimarySessionTests`. If `SessionRegistryTests` fails on a test that asserts the
record file is deleted, update that test — deletion is now deliberately wrong.

- [ ] **Step 5: Commit**

```bash
git add identity.py test_identity.py
git commit -m "feat(identity): key session records by Claude session, not pid"
```

---

## Task 2: Account name and a monotonic ordinal counter

**Files:**
- Modify: `identity.py` (add after `saved_fingerprint`, around line 220)
- Test: `test_identity.py`

**Interfaces:**
- Consumes: Task 1's `session_records()`.
- Produces:
  - `identity.account_name() -> str | None` — the stem, from `account_name` in
    `~/.antrozous/identity.json`, falling back to the name half of `agent_id`.
  - `identity.next_ordinal() -> int` — increments and persists `session_counter`.
  - `identity.seed_counter_from_records() -> int` — one-time migration helper.

- [ ] **Step 1: Write the failing tests**

```python
class AccountNameTests(IsolatedIdentityTest):
    def test_account_name_falls_back_to_the_saved_agent_id(self):
        identity.set_agent_id(self.home, "anish-bot.e5ox72jb")
        self.assertEqual(identity.account_name(), "anish-bot")

    def test_explicit_account_name_wins(self):
        identity.set_agent_id(self.home, "anish-bot-1.e5ox72jb")
        path = identity._global_path()
        record = identity._read_json(path)
        record["account_name"] = "anish-bot"
        identity._write_json(path, record)
        self.assertEqual(identity.account_name(), "anish-bot")

    def test_account_name_is_none_when_nothing_is_saved(self):
        self.assertIsNone(identity.account_name())


class OrdinalCounterTests(IsolatedIdentityTest):
    def setUp(self):
        super().setUp()
        identity.set_agent_id(self.home, "anish-bot.e5ox72jb")

    def test_counter_starts_at_one(self):
        self.assertEqual(identity.next_ordinal(), 1)

    def test_counter_increments_and_never_repeats(self):
        seen = [identity.next_ordinal() for _ in range(5)]
        self.assertEqual(seen, [1, 2, 3, 4, 5])
        self.assertEqual(len(set(seen)), 5)

    def test_counter_persists_across_reads(self):
        identity.next_ordinal()
        identity.next_ordinal()
        self.assertEqual(
            identity._read_json(identity._global_path())["session_counter"], 2
        )

    def test_counter_survives_a_rename(self):
        identity.next_ordinal()
        identity.next_ordinal()
        identity.set_agent_id(self.home, "renamed.e5ox72jb")
        self.assertEqual(identity.next_ordinal(), 3)

    def test_account_name_survives_a_rename(self):
        """_write_identity rebuilds the record from scratch; these keys must be
        carried forward with the fingerprint or a rename resets the ordinals."""
        path = identity._global_path()
        record = identity._read_json(path)
        record["account_name"] = "anish-bot"
        identity._write_json(path, record)
        identity.set_agent_id(self.home, "renamed.e5ox72jb")
        self.assertEqual(
            identity._read_json(path).get("account_name"), "anish-bot"
        )

    def test_seeding_lifts_the_counter_above_existing_ordinals(self):
        os.makedirs(identity.sessions_dir(), exist_ok=True)
        for n, name in enumerate(["anish-bot-2", "anish-bot-7", "anish-bot-3"]):
            with open(os.path.join(identity.sessions_dir(), "s%d.json" % n), "w") as f:
                json.dump({"agent_id": "%s.e5ox72jb" % name, "pid": None}, f)
        self.assertEqual(identity.seed_counter_from_records(), 7)
        self.assertEqual(identity.next_ordinal(), 8)

    def test_seeding_with_no_records_leaves_the_counter_alone(self):
        self.assertEqual(identity.seed_counter_from_records(), 0)
        self.assertEqual(identity.next_ordinal(), 1)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest test_identity.AccountNameTests test_identity.OrdinalCounterTests -v`
Expected: FAIL — `AttributeError: module 'identity' has no attribute 'account_name'`

- [ ] **Step 3: Implement**

Add to `identity.py`:

```python
ORDINAL_SUFFIX_RE = re.compile(r"^(?P<stem>.+)-(?P<ordinal>\d+)$")


def account_name():
    """The stem every session id is built from, or None on a fresh install.

    Stored explicitly so a saved id that already ends in a number (`anish-bot-1`)
    can be separated from the ordinal machinery rather than fighting it.
    """
    record = _read_json(_global_path()) or {}
    explicit = normalize_name(record.get("account_name") or "")
    if explicit:
        return explicit
    saved = record.get("agent_id")
    return normalize_name(agent_name(saved)) if saved else None


def next_ordinal():
    """Take the next session ordinal. Monotonic; never reuses a number.

    Reuse is the bug this replaces: picking the lowest ordinal not held by a LIVE
    session let a new session inherit a closed one's queue, which is the very
    cross-session drain inbox_addresses() refuses to perform.
    """
    path = _global_path()
    os.makedirs(global_dir(), exist_ok=True)
    record = _read_json(path) or {}
    current = record.get("session_counter")
    nxt = (current if isinstance(current, int) and current >= 0 else 0) + 1
    record["session_counter"] = nxt
    _write_json(path, record)
    return nxt


def seed_counter_from_records():
    """Lift the counter above every ordinal already used. Returns the high-water mark.

    Run once at migration: a queue already exists on the relay for those names, and
    handing the same ordinal out again would silently adopt it.
    """
    high = 0
    for rec in session_records().values():
        match = ORDINAL_SUFFIX_RE.match(agent_name(rec.get("agent_id") or ""))
        if match:
            high = max(high, int(match.group("ordinal")))
    if high:
        path = _global_path()
        os.makedirs(global_dir(), exist_ok=True)
        record = _read_json(path) or {}
        if (record.get("session_counter") or 0) < high:
            record["session_counter"] = high
            _write_json(path, record)
    return high
```

Then teach `_write_identity` (line 320) to carry the new keys forward. It rebuilds
the record from scratch and copies only `fingerprint`, `created_at`, `renamed_at`
and `previous_agent_id`, so without this a rename silently resets the ordinal
counter and the next session reuses a number that already has a queue:

```python
    existing = previous if previous is not None else _read_json(path)
    if existing:
        # Carried forward for the same reason as the fingerprint: these describe the
        # DEVICE, not the name, and a rename must not reset them. Dropping
        # session_counter would hand out an ordinal that already has a queue.
        for key in ("fingerprint", "account_name", "session_counter"):
            if existing.get(key) is not None:
                record[key] = existing[key]
```

replacing the existing two-line `if existing and existing.get("fingerprint"):` block.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m unittest test_identity -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add identity.py test_identity.py
git commit -m "feat(identity): account name and a monotonic session ordinal"
```

---

## Task 3: Derive the session id

**Files:**
- Modify: `identity.py` — replace `suggest_session_name` (line 179) and
  `suggest_session_id` (line 196)
- Test: `test_identity.py`

**Interfaces:**
- Consumes: `account_name()`, `next_ordinal()`, `saved_fingerprint()`.
- Produces: `identity.session_agent_id(ordinal, fingerprint=None) -> str | None`
  and `identity.fit_session_name(stem, ordinal) -> str` .

**Length constraint:** `NAME_RE` allows 2–33 characters, so `<stem>-<ordinal>` must
fit in 33. `fit_session_name` truncates the stem, never the ordinal — a truncated
ordinal would collide with another session.

- [ ] **Step 1: Write the failing tests**

```python
class SessionAgentIdTests(IsolatedIdentityTest):
    def setUp(self):
        super().setUp()
        identity.save_fingerprint("e5ox72jb")
        identity.set_agent_id(self.home, "anish-bot.e5ox72jb")

    def test_session_id_is_account_plus_ordinal(self):
        self.assertEqual(
            identity.session_agent_id(3), "anish-bot-3.e5ox72jb"
        )

    def test_session_id_uses_a_hyphen_not_a_dot(self):
        self.assertNotIn(".1.", identity.session_agent_id(1))

    def test_session_id_round_trips(self):
        sid = identity.session_agent_id(3)
        name, fp = identity.split_agent_id(sid)
        self.assertEqual(name, "anish-bot-3")
        self.assertEqual(fp, "e5ox72jb")
        self.assertEqual(identity.compose_agent_id(name, fp), sid)

    def test_session_id_matches_the_relay_grammar(self):
        relay = re.compile(
            r"^[a-z0-9][a-z0-9_-]{0,31}[a-z0-9]\.([a-z2-7]{8}|[a-z2-7]{16})$"
        )
        self.assertTrue(relay.match(identity.session_agent_id(12)))

    def test_a_long_account_name_is_truncated_to_fit(self):
        stem = "a" * 33
        fitted = identity.fit_session_name(stem, 100)
        self.assertLessEqual(len(fitted), 33)
        self.assertTrue(fitted.endswith("-100"))
        self.assertIsNotNone(identity.normalize_name(fitted))

    def test_session_id_is_none_without_an_account_name(self):
        os.unlink(identity._global_path())
        self.assertIsNone(identity.session_agent_id(1))
```

Add `import re` to `test_identity.py` if it is not already imported.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest test_identity.SessionAgentIdTests -v`
Expected: FAIL — `AttributeError: module 'identity' has no attribute 'session_agent_id'`

- [ ] **Step 3: Implement**

Delete `suggest_session_name` and `suggest_session_id` from `identity.py` and add:

```python
def fit_session_name(stem, ordinal):
    """'<stem>-<ordinal>', trimmed so it still satisfies NAME_RE (2-33 chars).

    The stem gives way, never the ordinal: a truncated ordinal could collide with
    another session, and a collision merges two inboxes.
    """
    tail = "-%d" % ordinal
    stem = (normalize_name(stem) or "agent")[: 33 - len(tail)].rstrip("-_")
    if not stem:
        stem = "a"
    return stem + tail


def session_agent_id(ordinal, fingerprint=None):
    """This session's full address, or None when there is no account name yet."""
    stem = account_name()
    if not stem:
        return None
    fp = fingerprint or saved_fingerprint()
    return compose_agent_id(fit_session_name(stem, ordinal), fp)
```

`suggest_session_id` has five callers in `test_identity.py` (lines 431, 475, 482,
490, 497, inside `SessionRegistryTests`). Delete those five assertions and the tests
that contain nothing else — they cover the ordinal-reuse behaviour this task
replaces, and `SessionAgentIdTests` above is their successor.

Then fix the two call sites that used the deleted helpers:

- `scripts/bootstrap_identity.py` — `suggested = identity.suggest_session_id(agent_id)`
  becomes the announcement built in Task 5. For now, replace with
  `suggested = identity.account_agent_id(identity.find_directory())`.
- `mcp_gate.py:678` — `_startup_suggested = identity.suggest_session_name(...)`
  is replaced wholesale in Task 4. For now, replace with
  `_startup_suggested = identity.account_name() or identity.agent_name(info["agent_id"])`.

- [ ] **Step 4: Run the whole suite**

Run: `python3 -m unittest discover -s . -p 'test_*.py'`
Expected: PASS except the pre-existing `test_auth.py` import error.

- [ ] **Step 5: Commit**

```bash
git add identity.py scripts/bootstrap_identity.py mcp_gate.py test_identity.py
git commit -m "feat(identity): derive session ids as <account>-<n>.<fingerprint>"
```

---

## Task 4: Gate adopts the derived id; popup only on first run

**Files:**
- Modify: `mcp_gate.py` — `offer_identity_setup` (659), `_handle_startup_reply` (696),
  `schedule_identity_setup` (589)
- Test: `test_session_rename.py`

**Interfaces:**
- Consumes: `identity.session_agent_id`, `identity.next_ordinal`,
  `identity.account_name`, Task 1's `register_session`.
- Produces: `mcp_gate.resume_or_assign_session_id() -> str | None` — the id this
  session adopts, reusing the record when one exists for this session key.

- [ ] **Step 0: Prepare `test_session_rename.py`**

The file imports `identity` only inside `setUp`. Add at module top, after the
existing imports:

```python
import contextlib

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
```

All new test classes below subclass `SessionRenameTest` (line 17), which already
redirects `ANTROZOUS_HOME`, stubs `_publish_identities`, and sets
`self.gate` / `self.identity` / `self.base`.

- [ ] **Step 1: Delete the tests whose premise this task removes**

Three tests in `test_session_rename.py` assert that a later launch prompts for a
name and renames the tab. That behaviour is being deleted, so the tests go with it —
they are not failing, they are describing the old contract:

- `test_later_launches_only_name_the_tab`
- `test_a_second_tab_names_itself_without_renaming_the_account`
- `test_the_prompt_says_which_one_it_is` — keep the first half (the FIRST-run
  assertions) and delete the second half, which asserts `"THIS TAB only"` appears in
  a later prompt.

Replace the first two with `test_new_session_takes_the_next_ordinal` and
`test_resumed_session_keeps_its_id` from Step 2, which cover what now happens
instead: a second session is numbered rather than named.

- [ ] **Step 2: Write the failing tests**

Add to `test_session_rename.py`:

```python
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
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `python3 -m unittest test_session_rename.SessionAdoptionTests -v`
Expected: FAIL — `AttributeError: module 'mcp_gate' has no attribute 'needs_account_setup'`

- [ ] **Step 4: Implement**

In `mcp_gate.py`:

```python
def needs_account_setup():
    """True only on a first run — no confirmed account name exists yet."""
    if os.environ.get("AGENT_ID", "").strip():
        return False
    info = identity.describe(identity.find_directory())
    return bool(info["needs_setup"]) or not identity.account_name()


def resume_or_assign_session_id():
    """This session's address: its own record if it has one, else the next ordinal.

    Reusing the record is what makes `claude --resume` come back to the same queue,
    and it is why a resumed session must not take a new ordinal.
    """
    existing = identity.session_records().get(identity.current_session_key())
    if existing and existing.get("agent_id"):
        return existing["agent_id"]
    if not identity.account_name():
        return None
    return identity.session_agent_id(identity.next_ordinal())
```

Change `schedule_identity_setup` so the delayed timer only fires when
`needs_account_setup()` is true. When it is false, adopt immediately instead:

```python
def schedule_identity_setup():
    """Claude Code discards elicitation received during initialization, so wait."""
    if not needs_account_setup():
        # Nothing to ask. Adopt the derived id now so the session is addressable
        # before the user's first turn.
        chosen = resume_or_assign_session_id()
        if chosen:
            _adopt_session_id(chosen)
            _publish_identities()
        return
    if STARTUP_DELAY <= 0:
        offer_identity_setup()
        return
    t = threading.Timer(STARTUP_DELAY, offer_identity_setup)
    t.daemon = True
    t.start()
```

In `_handle_startup_reply`, the accept branch now names the **account**. Replace the
block from `name = identity.normalize_name(chosen_name)` through
`log("session id set to", full_id)` with:

```python
    name = identity.normalize_name(chosen_name)
    if name is None:
        log("rejected account name %r; keeping saved id" % chosen_name)
        _adopt_session_id(identity.resolve_agent_id(base_dir))
        _publish_identities()
        return True

    account_id = identity.compose_agent_id(name, _startup_fingerprint) or name
    try:
        identity.set_agent_id(
            base_dir, account_id, drop_project_override=info["source"] == "project"
        )
        record = identity._read_json(identity._global_path()) or {}
        record["account_name"] = name
        identity._write_json(identity._global_path(), record)
    except (ValueError, OSError) as e:
        log("could not save account name:", e)

    chosen = resume_or_assign_session_id()
    _adopt_session_id(chosen or account_id)
    log("account is %s; this session is %s" % (account_id, chosen or account_id))
```

Rewrite `_session_prompt`'s copy for the first-run case only — it no longer has a
"names this tab" branch. Replace the `if info["needs_setup"]: ... else: ...` block
with a single string:

```python
    where = (
        "This name becomes YOUR ADDRESS — the one you give other people. It is "
        "chosen once. Each session you open is numbered from it automatically "
        "(%s-1, %s-2, ...), and you are never asked again. Use the set_identity "
        "tool later if you want to change it."
        % (suggested_name, suggested_name)
    )
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python3 -m unittest test_session_rename test_identity -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add mcp_gate.py test_session_rename.py
git commit -m "feat(gate): name the account once, derive every session id after"
```

---

## Task 5: One-line session announcement in the hook

**Files:**
- Modify: `scripts/bootstrap_identity.py` — the `__main__` block (line 132 onward)
- Test: `test_listener_state.py` (extend `HookResumeTests`)

**Interfaces:**
- Consumes: `identity.account_name()`, `identity.session_records()`,
  `identity.current_session_key()`.
- Produces: no new API. The hook's `systemMessage` gains a session line.

The hook runs **before** the gate assigns an ordinal, so it must not invent one. It
reports the record if this session already has one (a resume), and otherwise says the
id is being assigned.

- [ ] **Step 1: Write the failing tests**

```python
class HookAnnouncementTests(ListenerStateTest):
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

    def test_a_later_run_does_not_announce_a_popup(self):
        """Task 4 deleted the per-session popup. The hook must stop promising it."""
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
        payload = self.run_hook(AGENT_ID="", CLAUDE_CODE_SESSION_ID="sess-new")
        self.assertNotIn("prompt will appear", payload["systemMessage"])

    def test_a_first_run_still_announces_the_popup(self):
        payload = self.run_hook(AGENT_ID="", CLAUDE_CODE_SESSION_ID="sess-new")
        self.assertIn("prompt will appear", payload["systemMessage"])
```

`import identity` at the top of `test_listener_state.py` if it is not already there.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest test_listener_state.HookAnnouncementTests -v`
Expected: FAIL — the id is absent from the message.

- [ ] **Step 3: Implement**

In `scripts/bootstrap_identity.py`, add above `if __name__ == "__main__":`:

```python
def session_line():
    """One line naming this session, or '' when there is nothing settled to name.

    The hook runs BEFORE the gate assigns an ordinal, so a session with no record is
    reported as pending rather than guessed at — a guessed id that the gate then
    contradicts is worse than no id.
    """
    try:
        record = identity.session_records().get(identity.current_session_key())
        account = identity.account_name()
    except Exception:
        return ""
    if record and record.get("agent_id"):
        line = "\n  You are %s" % record["agent_id"]
        if account:
            line += " (front door: %s)" % identity.account_agent_id(
                identity.find_directory()
            )
        return line
    if account:
        return "\n  Assigning this session's id from %s." % account
    return ""
```

Also add, next to it:

```python
def will_prompt():
    """Whether the gate is about to raise the account-naming popup.

    It only fires on a first run now, so announcing one on every launch would
    promise a popup that never arrives.
    """
    try:
        return not identity.account_name()
    except Exception:
        return False
```

Then in the non-env branch of `__main__`, branch the announcement instead of always
promising a prompt:

```python
    if will_prompt():
        line = (
            "antrozous: choosing your Agent ID — a prompt will appear %s "
            "(suggested: %s). No need to type anything; just wait for it."
            % (human_delay(startup_delay()), suggested)
        )
    else:
        line = "antrozous: ready"
    if peers:
        line += "\n  Already running: %s" % ", ".join(sorted(peers.values()))
    emit(line + session_line() + resume_line, (FALLBACK_DIRECTIVE % agent_id) + resume_context)
```

`session_line()` supplies the identity on the non-prompting path, so "ready" is
never the whole message.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m unittest test_listener_state -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add scripts/bootstrap_identity.py test_listener_state.py
git commit -m "feat(hook): announce the session's full id at startup"
```

---

## Task 6: The front door — wire the primary slot to actually read

**Files:**
- Modify: `mcp_gate.py:540` (`inbox_addresses`)
- Test: `test_identity.py` and a new gate test

This is spec §6 and closes finding F2. `SKILL.md` already tells the model to arm a
second Monitor on `account_ws_url` when `is_primary`; this makes that true.

**Interfaces:**
- Consumes: `identity.is_primary()`, `mcp_gate.account_agent_id()`,
  `mcp_gate.current_agent_id()`.
- Produces: `inbox_addresses()` returns `[session]` or `[session, account]`.

- [ ] **Step 1: Write the failing test**

```python
class FrontDoorTests(SessionRenameTest):
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
```

`mock_primary` patches the function the gate actually calls. Define it in the test
file next to `_env`:

```python
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
```

Each test in this class needs an account id on disk, so add to the class:

```python
    def setUp(self):
        super().setUp()
        identity.save_fingerprint("e5ox72jb")
        identity.set_agent_id(self.base, "anish-bot.e5ox72jb")
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m unittest test_session_rename.FrontDoorTests -v`
Expected: FAIL — the primary case returns one address, not two.

- [ ] **Step 3: Implement**

Replace `inbox_addresses` in `mcp_gate.py`:

```python
def inbox_addresses():
    """The queues this session drains: its own, plus the front door if primary.

    Session queues are PRIVATE — a session never reads another live session's mail,
    because draining it would mean approving that session's messages on its behalf.

    The account address is different. It is the front door: the alias resolves to it
    (/resolve maps a bare name to a fingerprint and the sender composes
    <name>.<fingerprint>), first-claim-wins means it can never be repointed at a
    session, and so it belongs to no session. If nothing drained it, cold mail from
    a new contact would be invisible. Exactly one live session does — the primary.
    """
    session = current_agent_id()
    addresses = [session]
    if identity.is_primary():
        account = account_agent_id()
        if account and account != session:
            addresses.append(account)
    return addresses
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m unittest test_session_rename -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add mcp_gate.py test_session_rename.py
git commit -m "fix(gate): the primary session actually drains the front door"
```

---

## Task 7: Simplify whoami

**Files:**
- Modify: `mcp_gate.py:1296-1345` (`do_whoami` output block)
- Test: `test_session_rename.py`

Finding F1 lives here: the note claims outbound mail goes out as the account id. It
does not — `mcp_gate.py:840` uses `current_agent_id()`. Fix the copy to match the
code rather than the other way round; changing the wire format is out of scope.

- [ ] **Step 1: Write the failing tests**

```python
class WhoamiCopyTests(SessionRenameTest):
    def test_note_does_not_claim_mail_goes_out_as_the_account(self):
        out = whoami_payload()
        self.assertNotIn("your messages go out as", json.dumps(out).lower())

    def test_share_this_is_the_front_door(self):
        out = whoami_payload()
        self.assertEqual(out["share_this"], out["account_agent_id"])

    def test_sends_from_is_reported_and_is_the_session(self):
        out = whoami_payload()
        self.assertEqual(out["sends_from"], out["agent_id"])
```

`whoami_payload()` does not exist yet. `do_whoami` builds its dict inline and then
calls `tool_result`, which is not testable. Extracting the builder is part of this
task — see Step 3. In the tests, call `self.gate.whoami_payload()` and give the class
an account id in `setUp`:

```python
    def setUp(self):
        super().setUp()
        identity.save_fingerprint("e5ox72jb")
        identity.set_agent_id(self.base, "anish-bot.e5ox72jb")
        self.gate.SESSION_AGENT_ID = "anish-bot-2.e5ox72jb"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest test_session_rename.WhoamiCopyTests -v`
Expected: FAIL — `KeyError: 'sends_from'`

- [ ] **Step 3: Implement**

First extract the builder so it can be tested at all. In `mcp_gate.py`, split
`do_whoami` in two: move everything that constructs `out` into a new
`whoami_payload()` that returns the dict, and leave `do_whoami` to call it and hand
the result to `tool_result`. The early-return branch for a session with no identity
stays in `do_whoami` — it is an error path, not a payload.

```python
def whoami_payload():
    """The whoami dict. Split out of do_whoami so it can be asserted on directly."""
    ...  # the existing body, ending in `return out` instead of tool_result(...)
```

Then add `"sends_from": agent_id` to the `out` dict, and replace the first `note` branch
(the `if account != agent_id:` one) with:

```python
    if account != agent_id:
        out["note"] = (
            "Give people %s — that is your front door, and it stays the same in "
            "every session. This session sends as %s and drains its own queue; "
            "replies to what you send here come back to %s."
            % (account, agent_id, agent_id)
        )
```

Delete the `elif info["source"] == "project" and info["shadowed"]:` branch and the
`$AGENT_ID overrides` branch is kept. Keep the `not out["is_primary"]` branch but
correct it:

```python
    if account != agent_id and not out["is_primary"]:
        out["note"] = (
            "Another live session holds the primary slot, so front-door mail to %s "
            "is drained there, not here. This session drains %s."
            % (account, agent_id)
        )
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m unittest test_session_rename -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add mcp_gate.py test_session_rename.py
git commit -m "fix(gate): whoami describes the addresses the code actually uses"
```

---

## Task 8: `set_identity` becomes account-only

**Files:**
- Modify: `mcp_gate.py` — `do_set_identity` and `_identity_prompt`
- Test: `test_session_rename.py`

**Interfaces:**
- Consumes: `identity.account_name`, `identity.set_agent_id`.
- Produces: `set_identity` writes `account_name` alongside `agent_id`.

- [ ] **Step 1: Write the failing tests**

```python
class SetIdentityAccountTests(SessionRenameTest):
    def test_rename_writes_the_account_name(self):
        rename_to("newname")
        record = identity._read_json(identity._global_path())
        self.assertEqual(record["account_name"], "newname")

    def test_rename_does_not_change_this_session_id(self):
        before = self.gate.current_agent_id()
        rename_to("newname")
        self.assertEqual(self.gate.current_agent_id(), before)

    def test_prompt_says_the_alias_does_not_move(self):
        prompt, _ = self.gate._identity_prompt(
            identity.describe(self.home), "newname", "global", False
        )
        self.assertIn("alias", prompt.lower())
```

`rename_to(name)` does not exist. Define it as a method on the test class, stubbing
`_elicit` the way the existing rename tests stub `_publish_identities`:

```python
    def rename_to(self, name):
        real = self.gate._elicit
        self.gate._elicit = lambda message, schema=None: (
            "accept",
            {"agent_id": "%s.kbjz3w4a" % name},
        )
        try:
            self.gate.do_set_identity("rid-1", {"agent_id": "%s.kbjz3w4a" % name})
        finally:
            self.gate._elicit = real
```

Read `do_set_identity`'s accept branch before writing this — if it reads a different
key out of `content`, match that key rather than changing the production code.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest test_session_rename.SetIdentityAccountTests -v`
Expected: FAIL — `KeyError: 'account_name'`

- [ ] **Step 3: Implement**

In `do_set_identity`, after the successful `identity.set_agent_id(...)` call, write
the stem too:

```python
        record = identity._read_json(identity._global_path()) or {}
        record["account_name"] = identity.agent_name(canonical)
        identity._write_json(identity._global_path(), record)
```

Add to the prompt text built in `_identity_prompt`:

```
"Renaming changes the name new contacts see and the stem your sessions are "
"numbered from. It does NOT move the alias you already claimed: the relay binds "
"an alias to your KEY, first claim wins, so people who already have your old "
"name still reach you."
```

Do not change this session's id: renaming the account must not silently move the
queue this session is draining.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m unittest test_session_rename -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add mcp_gate.py test_session_rename.py
git commit -m "feat(gate): set_identity renames the account, not the session"
```

---

## Task 9: Migration — offer to strip a trailing ordinal, seed the counter

**Files:**
- Modify: `mcp_gate.py` — a new `offer_account_migration()` called from
  `schedule_identity_setup`
- Test: `test_session_rename.py`

Spec §10. Existing installs may have an account name that already ends in an ordinal
(the author's is `anish-bot-1.e5ox72jb`). Left alone, sessions become
`anish-bot-1-1`, `anish-bot-1-2`.

- [ ] **Step 1: Write the failing tests**

```python
class MigrationTests(SessionRenameTest):
    def test_trailing_ordinal_is_offered_for_stripping(self):
        identity.set_agent_id(self.home, "anish-bot-1.e5ox72jb")
        self.assertEqual(self.gate.migration_candidate(), "anish-bot")

    def test_a_clean_name_needs_no_migration(self):
        identity.set_agent_id(self.home, "anish-bot.e5ox72jb")
        self.assertIsNone(self.gate.migration_candidate())

    def test_a_name_that_is_only_digits_is_left_alone(self):
        identity.set_agent_id(self.home, "agent-42.e5ox72jb")
        self.assertEqual(self.gate.migration_candidate(), "agent")

    def test_declining_keeps_the_name_verbatim(self):
        identity.set_agent_id(self.home, "anish-bot-1.e5ox72jb")
        self.gate.apply_account_migration(accepted=False)
        self.assertEqual(identity.account_name(), "anish-bot-1")

    def test_accepting_strips_and_seeds_the_counter(self):
        identity.save_fingerprint("e5ox72jb")
        identity.set_agent_id(self.home, "anish-bot-1.e5ox72jb")
        os.makedirs(identity.sessions_dir(), exist_ok=True)
        with open(os.path.join(identity.sessions_dir(), "old.json"), "w") as f:
            json.dump({"agent_id": "anish-bot-4.e5ox72jb", "pid": None}, f)
        self.gate.apply_account_migration(accepted=True)
        self.assertEqual(identity.account_name(), "anish-bot")
        self.assertEqual(identity.next_ordinal(), 5)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest test_session_rename.MigrationTests -v`
Expected: FAIL — `AttributeError: ... has no attribute 'migration_candidate'`

- [ ] **Step 3: Implement**

```python
def migration_candidate():
    """The stem a legacy account name would become, or None if it is already clean.

    An account name ending in a number is almost always a session ordinal someone
    typed into the old per-session popup. Left in place, sessions become
    anish-bot-1-1, anish-bot-1-2.
    """
    record = identity._read_json(identity._global_path()) or {}
    if record.get("account_name"):
        return None
    name = identity.account_name()
    if not name:
        return None
    match = identity.ORDINAL_SUFFIX_RE.match(name)
    if not match:
        return None
    return identity.normalize_name(match.group("stem"))


def apply_account_migration(accepted):
    """Record the account stem. Always seeds the counter, whichever way it went."""
    name = migration_candidate() if accepted else identity.account_name()
    path = identity._global_path()
    record = identity._read_json(path) or {}
    if name:
        record["account_name"] = name
    identity._write_json(path, record)
    identity.seed_counter_from_records()
    return name
```

Call it from `schedule_identity_setup`'s non-first-run branch, before
`resume_or_assign_session_id()`. When `migration_candidate()` returns a name and the
client supports elicitation, ask first:

```python
    candidate = migration_candidate()
    if candidate and CLIENT_ELICITATION:
        action, _ = _elicit(
            "SHORTEN YOUR ANTROZOUS ADDRESS?\n\n"
            "Your address is %s. The '-%s' on the end looks like a session number "
            "that was typed into an older prompt.\n\n"
            "Sessions are now numbered from your address automatically, so keeping "
            "it would make this session %s-1.\n\n"
            "Accept = your address becomes %s.\n"
            "Decline = keep %s exactly as it is.\n\n"
            "Either way, people who already have your current name still reach you: "
            "the relay binds an alias to your key, not to the text."
            % (
                identity.account_name(),
                identity.account_name().rsplit("-", 1)[1],
                identity.account_name(),
                candidate,
                identity.account_name(),
            )
        )
        apply_account_migration(accepted=action == "accept")
    else:
        apply_account_migration(accepted=False)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m unittest discover -s . -p 'test_*.py'`
Expected: PASS except the pre-existing `test_auth.py` import error.

- [ ] **Step 5: Commit**

```bash
git add mcp_gate.py test_session_rename.py
git commit -m "feat(gate): offer to strip a session ordinal off a legacy account name"
```

---

## Task 10: Make the docs true

**Files:**
- Modify: `skills/antrozous-inbox/SKILL.md`, `README.md`,
  `docs/encryption-design.md`, `docs/identity-design.md`

No code, no tests. This closes the documentation half of F1, F2 and F3.

- [ ] **Step 1: Correct `SKILL.md` step 3**

It currently says "This session drains both inboxes." That is now true, but say *why*
so nobody deletes the Monitor as redundant:

```markdown
3. **If `whoami` reports `is_primary: true` and `account_agent_id` differs from
   `agent_id`, arm a SECOND Monitor on `account_ws_url` too.** The account address
   is the front door: anyone who addresses the user by their public name lands
   there, it belongs to no session, and the primary session is the one that drains
   it. Without this second Monitor, cold mail from a new contact never rings.
```

- [ ] **Step 2: Correct the `README.md` identity paragraph**

Replace the paragraph beginning "The identity is stored at `~/.antrozous/identity.json`"
with:

```markdown
Your identity lives at `~/.antrozous/identity.json` and follows you into every
directory. You choose the name once, on first run; it is your address, and it is
what you hand to other people. Each session you open is numbered from it
automatically — `anish-bot-1.<fingerprint>`, `anish-bot-2.<fingerprint>` — and those
numbers are never reused. A session keeps its number across `claude --resume`, so
messages that arrived while it was closed are still waiting for it.

Mail sent to your bare address lands in a shared front door that one live session
drains; mail sent to a session number is that session's alone. `set_identity`
renames the address, never a session.
```

- [ ] **Step 3: Correct `docs/encryption-design.md` §1**

It says the relay "holds it in the `inboxes` dict and mirrors it to `messages.json`."
The mirror does not exist — `BACKUP_FILE` is read at startup and never written.
Change that clause to "holds it in the `inboxes` dict **in memory only**; the
`messages.json` mirror named in `BACKUP_FILE` is read at startup and never written,
so a redeploy drops every queue."

- [ ] **Step 4: Mark the spec implemented**

In `docs/identity-design.md`, change `Status: proposal, not implemented.` to
`Status: implemented, <date>.` and strike §13 if Task 0 resolved it.

- [ ] **Step 5: Commit**

```bash
git add skills/antrozous-inbox/SKILL.md README.md docs/
git commit -m "docs: describe the identity model the code now implements"
```

---

## Definition of done

- [ ] Task 0 verified and its outcome recorded in the spec.
- [ ] `python3 -m unittest discover -s . -p 'test_*.py'` passes, with only the
      pre-existing `test_auth.py` import error.
- [ ] `claude plugin validate ./antrozous` passes from the parent directory.
- [ ] A fresh install (`ANTROZOUS_HOME` pointed at an empty dir) prompts once, then
      never again, and reports `<account>-1.<fingerprint>`.
- [ ] A second concurrent session reports `-2` and does not disturb the first.
- [ ] `claude --resume` on the first session reports `-1` again.
- [ ] `~/.antrozous/sessions/` accumulates records and nothing deletes them.
