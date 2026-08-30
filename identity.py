import contextlib
import os
import re
import json
import secrets
import subprocess
import threading

from datetime import datetime

try:
    import fcntl
except ImportError:  # Windows has no fcntl; the identity record degrades to unlocked.
    fcntl = None

GIT_EXCLUDE_PATTERN = ".antrozous/"

# Ids are interpolated unescaped into /inbox/<id> and /ws/<id>.
AGENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}[a-z0-9]$")

# A qualified id is "<name>.<fingerprint>". The fingerprint is a digest of the
# agent's identity key, so two people who choose the same name still get different
# ids instead of silently sharing an inbox.
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}[a-z0-9]$")
FINGERPRINT_RE = re.compile(r"^[a-z2-7]{8}$")

# A session key becomes a filename, so it is restricted to characters that cannot
# escape the sessions directory. Claude Code's session id is a UUID and fits.
SESSION_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def normalize_name(candidate):
    """Canonical form of the human-chosen part of an id, or None if illegal."""
    if not isinstance(candidate, str):
        return None
    folded = candidate.strip().lower()
    if "." in folded:
        folded = folded.split(".", 1)[0]
    return folded if NAME_RE.match(folded) else None


def compose_agent_id(name, fingerprint):
    normalized = normalize_name(name)
    if normalized is None:
        return None
    if not (isinstance(fingerprint, str) and FINGERPRINT_RE.match(fingerprint)):
        return normalized
    return "%s.%s" % (normalized, fingerprint)


def split_agent_id(agent_id):
    """(name, fingerprint) — fingerprint is None for a legacy unqualified id."""
    if not isinstance(agent_id, str) or "." not in agent_id:
        return agent_id, None
    name, _, tail = agent_id.rpartition(".")
    if FINGERPRINT_RE.match(tail) and normalize_name(name):
        return name, tail
    return agent_id, None


def agent_name(agent_id):
    return split_agent_id(agent_id)[0]


def is_qualified(agent_id):
    return split_agent_id(agent_id)[1] is not None


def global_dir():
    return os.environ.get("ANTROZOUS_HOME") or os.path.expanduser("~/.antrozous")


def _global_path():
    return os.path.join(global_dir(), "identity.json")


def sessions_dir():
    return os.path.join(global_dir(), "sessions")


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


def _pid_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


# A pid on its own is not an identity. The OS recycles pids, and session records
# are never pruned (see session_records), so a record left behind by a SIGKILLed,
# crashed or power-cut session sits on disk until its pid comes round again --
# at which point _pid_alive() starts reporting an unrelated process as that
# session. Before records became permanent the exposure was minutes, because every
# scan unlinked the dead ones; now it is unbounded, and a stale
# {"pid": N, "primary": true} that reads live wedges the front door: claim_primary()
# refuses forever, nothing drains the account address, and whoami reports a phantom
# session. After a reboot every stale pid is a recycling candidate at once.
#
# What closes it is a marker for the pid's GENERATION, stored beside the pid and
# re-derived from the OS at scan time: the holder's process START TIME.
#
# Chosen over a boot identifier because it also separates two generations of one
# pid WITHIN a single boot, and because both sources below are values the kernel
# records once at fork and never recomputes, so nothing makes them drift under a
# live holder:
#   - procfs (Linux, WSL): field 22 of /proc/<pid>/stat, ticks since boot. No
#     subprocess, no locale, no clock.
#   - everywhere else: `ps -o lstart=`, the wall clock stamped at fork. Run under
#     LC_ALL=C so a locale change between the write and the read cannot fake a
#     mismatch.
#
# macOS's obvious boot identifier, `sysctl kern.boottime`, was rejected for the
# same reason: the kernel moves it whenever the wall clock is stepped, and a marker
# that changes under a live holder marks every running session dead at once --
# which costs two sessions both draining the front door, the very isolation
# inbox_addresses() exists to keep.
_PID_START_KEY = "pid_start"

# Guard against handing `ps` something it will reject outright: an out-of-range pid
# makes it fail the WHOLE listing (exit 1, no output), which would read as "every
# one of these pids is dead". _pid_alive() already filters those out, so this is a
# second belt on the same trousers.
_PID_MAX = 1 << 22


def _pid_start_from_proc(pid):
    """Field 22 of /proc/<pid>/stat, or None."""
    try:
        with open("/proc/%d/stat" % pid, "rb") as f:
            data = f.read()
    except OSError:
        return None
    # comm is parenthesised and may itself contain spaces and ')', so split on the
    # LAST ')' rather than tokenising from the left. The first field after it is
    # state (field 3), so field 22 is index 19.
    fields = data.rpartition(b")")[2].split()
    if len(fields) < 20:
        return None
    try:
        return fields[19].decode("ascii")
    except UnicodeDecodeError:
        return None


def _pid_starts_from_ps(pids):
    """{pid: 'lstart' string} via one ps call, or None if ps cannot be used."""
    try:
        result = subprocess.run(
            ["ps", "-o", "pid=,lstart=", "-p", ",".join(str(p) for p in sorted(pids))],
            capture_output=True,
            text=True,
            timeout=2,
            env=dict(os.environ, LC_ALL="C"),
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    # 0 = at least one matched, 1 = none of them exist any more. Anything else is
    # ps failing rather than answering, and must NOT be read as "all dead".
    if result.returncode not in (0, 1):
        return None
    out = {}
    for line in result.stdout.splitlines():
        head, _, rest = line.strip().partition(" ")
        if not (head.isdigit() and rest.strip()):
            continue
        out[int(head)] = rest.strip()
    return out


def _pid_start_times(pids):
    """{pid: start-time marker} for `pids`, or None when the platform cannot say.

    None and {} are deliberately different answers. None means "no generation
    information available here" and callers must fall back to a bare pid check --
    i.e. to the pre-marker behaviour, because a platform that cannot answer must
    not have every one of its sessions declared dead. {} means the query worked and
    none of those pids exist any more.
    """
    wanted = {p for p in pids if isinstance(p, int) and 0 < p < _PID_MAX}
    if not wanted:
        return {}
    if os.path.isdir("/proc/%d" % os.getpid()):
        return {
            pid: marker
            for pid, marker in ((p, _pid_start_from_proc(p)) for p in wanted)
            if marker is not None
        }
    return _pid_starts_from_ps(wanted)


def pid_start_marker(pid=None):
    """This process's (or `pid`'s) generation marker, or None if unobtainable."""
    pid = os.getpid() if pid is None else pid
    starts = _pid_start_times({pid})
    return (starts or {}).get(pid)


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
    """{session_key: record} for records whose process is still running.

    "Still running" is the pid AND its generation marker (see _PID_START_KEY): a
    recycled pid is a different process, not a resurrected session.

    A record written before the marker existed carries none, and is treated as
    DEAD. The two errors are not symmetric. A false "alive" is permanent and
    wedges the front door -- the defect this marker exists to remove -- while a
    false "dead" costs at most a briefly double-claimed primary slot and
    self-corrects the moment the session in question next registers, which every
    session does at startup. Marker-less records therefore come from processes
    started before this code was installed; those are overwhelmingly already dead,
    and the one that is not is a session whose gate will re-register with a marker
    on its next launch. A one-time migration was rejected because there is nothing
    to migrate them WITH: no marker can be invented after the fact for a pid whose
    generation nobody recorded.

    Identity is unaffected: session_records() still returns every record, so a
    resumed session finds its own address regardless of what liveness says.
    """
    records = session_records()
    candidates = {
        key: rec
        for key, rec in records.items()
        if isinstance(rec.get("pid"), int) and _pid_alive(rec["pid"])
    }
    starts = _pid_start_times({rec["pid"] for rec in candidates.values()})
    if starts is None:
        # Platform cannot report process start times. Degrade to the bare pid
        # check rather than declaring every session dead.
        return candidates
    return {
        key: rec
        for key, rec in candidates.items()
        if rec.get(_PID_START_KEY) is not None
        and rec.get(_PID_START_KEY) == starts.get(rec["pid"])
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
    # Only the SAME live process re-registering (a rename) may carry the primary
    # flag forward untouched. Any other case sharing this session key — a resume
    # under a new pid, or a record a crashed process left behind — must not
    # resurrect a stale flag: claim_primary() decides afresh, next line, in the
    # caller. Without this, a SIGKILLed primary's record (never pruned) can hand
    # its flag to a resumed session while a second session already claimed the
    # vacant slot, leaving two live primaries at once.
    marker = pid_start_marker()
    was_primary = (
        bool(record.get("primary"))
        and record.get("pid") == os.getpid()
        # Same pid is not the same process once pids recycle, so the flag only
        # carries forward when the generation matches too.
        and record.get(_PID_START_KEY) == marker
    )
    record.update(
        {
            "claude_session_id": current_session_key(),
            "agent_id": agent_id,
            "pid": os.getpid(),
            "started_at": record.get("started_at") or str(datetime.now()),
            "last_seen_at": str(datetime.now()),
        }
    )
    if marker is None:
        record.pop(_PID_START_KEY, None)
    else:
        record[_PID_START_KEY] = marker
    if primary or was_primary:
        record["primary"] = True
    else:
        record.pop("primary", None)
    _write_json(_session_path(), record)
    return agent_id


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


def is_primary():
    return primary_pid() == os.getpid()


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
    record.pop(_PID_START_KEY, None)
    record.pop("primary", None)
    record["last_seen_at"] = str(datetime.now())
    try:
        _write_json(_session_path(), record)
    except OSError:
        pass


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


def account_agent_id(base_dir):
    """The stable address to hand to other people.

    Built from the SAVED default name plus this device's fingerprint, so it is the
    same in every session. Session addresses vary by name; this one does not.
    """
    saved = resolve_agent_id(base_dir)
    name, fp = split_agent_id(saved)
    return compose_agent_id(name, fp or saved_fingerprint()) or saved


def saved_fingerprint():
    return (_read_json(_global_path()) or {}).get("fingerprint")


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


def has_explicit_account_name():
    """True once the account name has been recorded on purpose (set_account_name,
    directly or via a first-run/migration prompt) rather than merely being
    derivable from a saved agent_id.

    Public so callers deciding whether to OFFER to set the account name -- the
    legacy-ordinal migration prompt is the one that needs this -- do not have to
    reach into _read_json(_global_path()) themselves to ask.
    """
    record = _read_json(_global_path()) or {}
    return bool(normalize_name(record.get("account_name") or ""))


def _identity_lock_path():
    return os.path.join(global_dir(), ".identity.lock")


# flock is a CROSS-process primitive only: two fds on one file, even from the same
# process, are independent lock holders, so a nested _identity_lock() would block on
# its own outer lock forever. set_agent_id() -> _write_identity() is exactly that
# shape. These two make the lock reentrant within a process (depth) and mutually
# exclusive between this process's threads (RLock) -- the latter is not academic:
# mcp_gate runs ensure_keys() -> save_fingerprint(), via the identity prompt, off a
# threading.Timer while the main thread is in set_agent_id().
_LOCAL_LOCK = threading.RLock()
_LOCAL_DEPTH = 0


def _take_flock():
    """Open the lock file and hold an exclusive flock on it. None if unavailable.

    Best-effort by design: if fcntl is missing (Windows) or flock raises OSError
    (some network filesystems), the caller proceeds WITHOUT the lock rather than
    failing. A missing lock must never stop a session from starting; on such a
    platform the race simply remains, which is exactly the pre-lock behavior.

    Known, accepted stall: this runs with _LOCAL_LOCK already held and LOCK_EX has
    no timeout, so a cross-process holder that is wedged rather than dead blocks
    every identity write in THIS process, including the ones other threads are
    waiting on behind _LOCAL_LOCK. The kernel releases flock when a holder exits or
    is killed, so this needs a live-but-stuck holder to happen at all; a timeout
    here would trade that for unguarded writes, which is the ordinal-reuse hazard
    the lock exists to prevent.
    """
    if fcntl is None:
        return None
    try:
        os.makedirs(global_dir(), exist_ok=True)
        fd = os.open(_identity_lock_path(), os.O_CREAT | os.O_RDWR, 0o644)
    except OSError:
        return None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
    except OSError:
        os.close(fd)
        return None
    return fd


@contextlib.contextmanager
def _identity_lock():
    """Cross-process mutex around the GLOBAL identity record as a whole.

    Scoped to the record, not to the counter: save_fingerprint(), mark_confirmed(),
    set_agent_id()/_write_identity() and _generate_and_persist() all read
    identity.json, mutate a dict and write it back, exactly as the counter does. A
    counter-only lock left those unguarded, so a session could read
    session_counter=N, be overtaken by next_ordinal() persisting N+1, and then land
    its own write and put the counter back to N -- handing N+1 out twice. Two
    sessions on one ordinal share an agent id, hence a relay queue, hence each
    other's mail.

    A dedicated lock file, separate from identity.json and never replaced: flock is
    scoped to the file's inode, and _write_json replaces identity.json's inode on
    every write via os.replace, so a lock taken on that path directly would end up
    guarding an orphaned file. This file is only ever opened and flock'd, never
    swapped out, so the lock stays meaningful across writers.

    flock is released by the kernel the instant the holding process exits or is
    killed, so unlike an O_CREAT|O_EXCL marker (identity.py's own primary-session
    flag, keys.py's key file) this has no stale-lock failure mode -- a process
    SIGKILLed mid-write cannot wedge the next session.

    Reentrant: taking it while this thread already holds it is a no-op that runs
    inside the existing lock, so set_agent_id() may take it and still call
    _write_identity(), which takes it too.
    """
    global _LOCAL_DEPTH
    with _LOCAL_LOCK:
        if _LOCAL_DEPTH:
            _LOCAL_DEPTH += 1
            try:
                yield
            finally:
                _LOCAL_DEPTH -= 1
            return
        fd = _take_flock()
        _LOCAL_DEPTH = 1
        try:
            yield
        finally:
            _LOCAL_DEPTH = 0
            if fd is not None:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(fd)


def next_ordinal():
    """Take the next session ordinal.

    Monotonic and collision-free wherever _identity_lock() actually locks, which is
    every platform with a working fcntl. Where it cannot (Windows, some network
    filesystems) it degrades to an unguarded read-modify-write and two sessions
    started at the same instant can still be handed the same number -- so the
    guarantee is "never reuses a number under the lock", not unconditionally.

    Reuse is the bug this replaces: picking the lowest ordinal not held by a LIVE
    session let a new session inherit a closed one's queue, which is the very
    cross-session drain inbox_addresses() refuses to perform.
    """
    path = _global_path()
    os.makedirs(global_dir(), exist_ok=True)
    with _identity_lock():
        record = _read_json(path) or {}
        current = record.get("session_counter")
        nxt = (current if isinstance(current, int) and current >= 0 else 0) + 1
        record["session_counter"] = nxt
        _write_json(path, record)
        return nxt


def seed_counter_from_records():
    """Lift the counter above every ordinal already used. Returns the high-water mark.

    Run once at migration: a queue already exists on the relay for those names, and
    handing the same ordinal out again would silently adopt it. Shares
    _identity_lock() with next_ordinal() and every other writer of the record, so a
    concurrent seed and increment cannot interleave into a lost update. The
    session_records() scan stays OUTSIDE the lock: it reads the sessions directory,
    not the global record, and holding the lock across it would only lengthen the
    window other sessions wait on.
    """
    high = 0
    for rec in session_records().values():
        match = ORDINAL_SUFFIX_RE.match(agent_name(rec.get("agent_id") or ""))
        if match:
            high = max(high, int(match.group("ordinal")))
    if high:
        path = _global_path()
        os.makedirs(global_dir(), exist_ok=True)
        with _identity_lock():
            record = _read_json(path) or {}
            if (record.get("session_counter") or 0) < high:
                record["session_counter"] = high
                _write_json(path, record)
    return high


def save_fingerprint(fp):
    """Cache the gate's key fingerprint so crypto-free callers can build full ids.

    Under _identity_lock() like every other writer of the record. Unguarded, the
    gate's startup call to this ran concurrently with the same session's
    next_ordinal(), read a session_counter that next_ordinal() then incremented,
    and wrote the stale value back -- handing the same ordinal to two sessions.
    """
    if not (isinstance(fp, str) and FINGERPRINT_RE.match(fp)):
        return None
    path = _global_path()
    os.makedirs(global_dir(), exist_ok=True)
    with _identity_lock():
        record = _read_json(path) or {}
        if record.get("fingerprint") == fp:
            return fp
        record["fingerprint"] = fp
        if not record.get("agent_id"):
            record["agent_id"] = suggest_agent_id(scope="global")
            record.setdefault("created_at", str(datetime.now()))
            record.setdefault("confirmed", False)
        _write_json(path, record)
    return fp


def _identity_path(base_dir):
    return os.path.join(base_dir, ".antrozous", "identity.json")


def _read_json(filename: str):
    try:
        with open(filename, "r") as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def _write_json(path, record):
    # Per-process temp name. A single shared `path + ".tmp"` meant two processes
    # writing the same target wrote the SAME temp file, so the loser's os.replace
    # could fire after the winner had already renamed it away -- a bare
    # FileNotFoundError out of the function whose whole job is an atomic write.
    # _identity_lock() serializes the global record, but this also covers the
    # per-session files under sessions_dir(), which nothing locks.
    tmp = "%s.tmp.%d" % (path, os.getpid())
    with open(tmp, "w") as f:
        json.dump(record, f)
    os.replace(tmp, path)


def _ensure_git_excluded(base_dir):
    """Keep project identity state out of Git without editing tracked files."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--git-path", "info/exclude"],
            cwd=base_dir,
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        )
        exclude_path = result.stdout.strip()
        if not exclude_path:
            return
        if not os.path.isabs(exclude_path):
            exclude_path = os.path.join(base_dir, exclude_path)

        try:
            with open(exclude_path, "r", encoding="utf-8") as file:
                patterns = {line.strip() for line in file}
        except FileNotFoundError:
            patterns = set()

        if GIT_EXCLUDE_PATTERN not in patterns:
            os.makedirs(os.path.dirname(exclude_path), exist_ok=True)
            with open(exclude_path, "a", encoding="utf-8") as file:
                if os.path.exists(exclude_path) and os.path.getsize(exclude_path):
                    file.write("\n")
                file.write(GIT_EXCLUDE_PATTERN + "\n")
    except (FileNotFoundError, NotADirectoryError, OSError, subprocess.SubprocessError):
        pass


def normalize_agent_id(candidate):
    """Canonical form of a user-supplied id, or None if illegal."""
    if not isinstance(candidate, str):
        return None
    folded = candidate.strip().lower()
    return folded if AGENT_ID_RE.match(folded) else None


def _slugify(text):
    return re.sub(r"[^a-z0-9]+", "-", text.strip().lower()).strip("-")[:32]


def suggest_agent_id(base_dir=None, scope="global"):
    """Global scope names the user; project scope names the directory."""
    if scope == "global":
        slug = _slugify(os.environ.get("USER") or os.environ.get("LOGNAME") or "")
        candidate = "agent-%s" % slug if slug else "agent-%s" % secrets.token_hex(5)
    else:
        slug = _slugify(os.path.basename(os.path.abspath(base_dir or os.getcwd())))
        # Random tail: relay ids share one namespace and a collision merges inboxes.
        candidate = (
            "agent-%s-%s" % (slug, secrets.token_hex(2))
            if slug
            else "agent-%s" % secrets.token_hex(5)
        )
    return normalize_agent_id(candidate) or "agent-" + secrets.token_hex(5)


def _write_identity(path, agent_id, previous=None, confirmed=True):
    """Rebuild the identity record at `path` from scratch and write it.

    Takes _identity_lock() even though its only callers already hold it: the lock is
    reentrant, so the redundant take costs nothing, and it means this cannot be
    called unguarded by a future caller who does not know the contract. Without the
    lock a rename read a record, rebuilt it, and wrote back a session_counter that
    another session had incremented in between.
    """
    with _identity_lock():
        record = {"agent_id": agent_id, "confirmed": bool(confirmed)}
        # The fingerprint is cached here for crypto-free readers; a rename must
        # not drop it or the hook loses the ability to build qualified ids.
        existing = previous if previous is not None else _read_json(path)
        if existing:
            # A rename only replaces agent_id; none of these should reset with it.
            # fingerprint identifies the device. session_counter is the device's
            # ordinal high-water mark — dropping it would hand out a number that
            # already has a queue. account_name is the user's chosen stem, set once
            # and independent of whatever id a particular session ends up with.
            for key in ("fingerprint", "account_name", "session_counter"):
                if existing.get(key) is not None:
                    record[key] = existing[key]
        if previous and previous.get("created_at"):
            record["created_at"] = previous["created_at"]
            record["renamed_at"] = str(datetime.now())
            if previous.get("agent_id") and previous["agent_id"] != agent_id:
                record["previous_agent_id"] = previous["agent_id"]
        else:
            record["created_at"] = str(datetime.now())
        _write_json(path, record)
    return agent_id


def set_agent_id(base_dir, new_id, scope="global", drop_project_override=False):
    """Set the agent id and mark it confirmed. Returns the canonical id.

    drop_project_override deletes a project file that would otherwise shadow the
    global id being written.
    """
    canonical = normalize_agent_id(new_id)
    if canonical is None:
        raise ValueError(
            "invalid agent id %r — use 2-64 chars of a-z, 0-9, dot, dash or "
            "underscore, starting and ending alphanumeric" % (new_id,)
        )

    if scope == "project":
        os.makedirs(os.path.join(base_dir, ".antrozous"), exist_ok=True)
        # Deliberately outside the lock: this shells out to git with a 2s timeout
        # and touches only .git/info/exclude, so holding the identity lock across
        # it would stall every other session for no protection.
        _ensure_git_excluded(base_dir)
        path = _identity_path(base_dir)
        with _identity_lock():
            return _write_identity(path, canonical, previous=_read_json(path))

    project_path = _identity_path(base_dir)
    path = _global_path()
    os.makedirs(global_dir(), exist_ok=True)
    # One lock spans the read of `previous` through the write, so a concurrent
    # next_ordinal() cannot slip an increment in between and lose it.
    with _identity_lock():
        project_record = _read_json(project_path)
        previous = _read_json(path) or (
            project_record if drop_project_override else None
        )
        _write_identity(path, canonical, previous=previous)

        if drop_project_override and project_record:
            # Global write first: a failed unlink leaves us un-consolidated, not
            # id-less.
            try:
                os.unlink(project_path)
            except OSError:
                pass
    return canonical


def mark_confirmed(base_dir):
    """Keep the current id but stop prompting for it. Marks the file in force.

    Under _identity_lock(): this rewrites the whole record to flip one flag, so
    unguarded it would drop any key another process wrote after its read -- the
    session counter included.
    """
    with _identity_lock():
        for path in (_identity_path(base_dir), _global_path()):
            data = _read_json(path)
            if not (data and data.get("agent_id")):
                continue
            if not data.get("confirmed"):
                data["confirmed"] = True
                _write_json(path, data)
            return data["agent_id"]
    return None


def set_account_name(name):
    """Record the human-chosen stem every session id is derived from.

    Under _identity_lock() like every other writer of the global record.
    Unguarded, this is a read-modify-write racing next_ordinal()'s own
    read-modify-write of the same file: whichever writes last wins outright,
    silently dropping the other's change -- and when the dropped change is a
    freshly incremented session_counter, the ordinal it protected gets handed
    out again to the next session that asks.
    """
    normalized = normalize_name(name)
    if normalized is None:
        raise ValueError("invalid account name %r" % (name,))
    path = _global_path()
    os.makedirs(global_dir(), exist_ok=True)
    with _identity_lock():
        record = _read_json(path) or {}
        record["account_name"] = normalized
        _write_json(path, record)
    return normalized


def _generate_and_persist():
    """First-run creation of the global record. O_CREAT|O_EXCL, under the lock.

    The exclusive create makes this safe against another _generate_and_persist, but
    not against a writer that is mid-read-modify-write: that writer read no file,
    this one creates it, and then the writer's os.replace drops the id again. The
    shared lock is what closes that.

    Not atomic: between os.open() and the write completing, the file exists but is
    empty, so an unlocked reader landing in that exact window sees "no record"
    (_read_json turns the resulting JSONDecodeError into None) rather than a torn
    one. That is benign and self-correcting, not a bug to fix here -- this path
    runs once, on a fresh install, and a reader that sees "no record" simply goes on
    to create one itself (racing this call, resolved by the O_CREAT|O_EXCL above) or
    to take the lock. Unlike _write_json's writes, which do land via an atomic
    os.replace, this one does not, and nothing downstream depends on it doing so.
    """
    os.makedirs(global_dir(), exist_ok=True)
    path = _global_path()
    candidate = suggest_agent_id(scope="global")
    with _identity_lock():
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            with os.fdopen(fd, "w") as f:
                json.dump(
                    {
                        "agent_id": candidate,
                        "created_at": str(datetime.now()),
                        "confirmed": False,
                    },
                    f,
                )
            return candidate
        except FileExistsError:
            return _read_json(path)["agent_id"]


def find_directory():
    return os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()


def resolve_agent_id(base_dir):
    """env AGENT_ID > project .antrozous/ > ~/.antrozous/ > generate (global)."""
    v = os.environ.get("AGENT_ID", "")
    if v.strip():
        return v.strip()
    project = _read_json(_identity_path(base_dir))
    if project and project.get("agent_id"):
        _ensure_git_excluded(base_dir)
        return project["agent_id"]
    glob = _read_json(_global_path())
    if glob and glob.get("agent_id"):
        return glob["agent_id"]
    return _generate_and_persist()


def describe(base_dir):
    """resolve_agent_id plus provenance.

    Returns agent_id, source (env|project|global|generated), path, global_path,
    project_path, shadowed (the id the winning tier hides), needs_setup.
    """
    project_path = _identity_path(base_dir)
    global_path = _global_path()
    project = _read_json(project_path) or {}
    glob = _read_json(global_path) or {}
    project_id, global_id = project.get("agent_id"), glob.get("agent_id")

    base = {"global_path": global_path, "project_path": project_path}

    env = os.environ.get("AGENT_ID", "").strip()
    if env:
        below = project_id or global_id
        return dict(
            base,
            agent_id=env,
            source="env",
            path=None,
            shadowed=below if below and below != env else None,
            needs_setup=False,
        )

    if project_id:
        return dict(
            base,
            agent_id=project_id,
            source="project",
            path=project_path,
            shadowed=global_id if global_id and global_id != project_id else None,
            needs_setup=not project.get("confirmed", False),
        )

    if global_id:
        return dict(
            base,
            agent_id=global_id,
            source="global",
            path=global_path,
            shadowed=None,
            needs_setup=not glob.get("confirmed", False),
        )

    agent_id = resolve_agent_id(base_dir)
    glob = _read_json(global_path) or {}
    return dict(
        base,
        agent_id=agent_id,
        source="generated",
        path=global_path,
        shadowed=None,
        needs_setup=not glob.get("confirmed", False),
    )
