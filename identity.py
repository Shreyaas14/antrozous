import contextlib
import os
import re
import json
import secrets
import subprocess

from datetime import datetime

try:
    import fcntl
except ImportError:  # Windows has no fcntl; the counter degrades to unlocked.
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
    # Only the SAME live process re-registering (a rename) may carry the primary
    # flag forward untouched. Any other case sharing this session key — a resume
    # under a new pid, or a record a crashed process left behind — must not
    # resurrect a stale flag: claim_primary() decides afresh, next line, in the
    # caller. Without this, a SIGKILLed primary's record (never pruned) can hand
    # its flag to a resumed session while a second session already claimed the
    # vacant slot, leaving two live primaries at once.
    was_primary = bool(record.get("primary")) and record.get("pid") == os.getpid()
    record.update(
        {
            "claude_session_id": current_session_key(),
            "agent_id": agent_id,
            "pid": os.getpid(),
            "started_at": record.get("started_at") or str(datetime.now()),
            "last_seen_at": str(datetime.now()),
        }
    )
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
    record.pop("primary", None)
    record["last_seen_at"] = str(datetime.now())
    try:
        _write_json(_session_path(), record)
    except OSError:
        pass


def suggest_session_name(base):
    """base if no live session uses that name, else base-2, base-3, …

    Tabs on one machine share a fingerprint, so distinctness between them has to
    come from the name.
    """
    base = normalize_name(base) or "agent"
    taken = {agent_name(a) for a in live_sessions().values()}
    if base not in taken:
        return base
    for n in range(2, 100):
        candidate = normalize_name("%s-%d" % (base, n))
        if candidate and candidate not in taken:
            return candidate
    return normalize_name("%s-%s" % (base, secrets.token_hex(2))) or base


def suggest_session_id(base):
    """A free, fully qualified id derived from `base`.

    Falls back to the cached fingerprint when `base` is an unqualified legacy id, so
    the suggestion is collision-proof even before the id has been migrated.
    """
    name, fp = split_agent_id(base)
    suggested = suggest_session_name(name)
    return compose_agent_id(suggested, fp or saved_fingerprint()) or suggested


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


def _counter_lock_path():
    return os.path.join(global_dir(), ".counter.lock")


@contextlib.contextmanager
def _counter_lock():
    """Best-effort cross-process mutex around the counter's read-modify-write.

    A dedicated lock file, separate from identity.json and never replaced: flock
    is scoped to the file's inode, and _write_json replaces identity.json's inode
    on every write via os.replace, so a lock taken on that path directly would end
    up guarding an orphaned file. This file is only ever opened and flock'd, never
    swapped out, so the lock stays meaningful across writers.

    flock is released by the kernel the instant the holding process exits or is
    killed, so unlike an O_CREAT|O_EXCL marker (identity.py's own primary-session
    flag, keys.py's key file) this has no stale-lock failure mode — a process
    SIGKILLed mid-increment cannot wedge the next session.

    Best-effort: if fcntl is unavailable (Windows) or flock raises OSError (some
    network filesystems), proceed WITHOUT the lock rather than failing the caller.
    A missing lock must never stop a session from starting; on such a platform the
    race simply remains, which is exactly today's behavior, so nothing regresses.
    """
    if fcntl is None:
        yield
        return
    os.makedirs(global_dir(), exist_ok=True)
    try:
        fd = os.open(_counter_lock_path(), os.O_CREAT | os.O_RDWR, 0o644)
    except OSError:
        yield
        return
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
        except OSError:
            yield
            return
        try:
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
    finally:
        os.close(fd)


def next_ordinal():
    """Take the next session ordinal. Monotonic; never reuses a number.

    Reuse is the bug this replaces: picking the lowest ordinal not held by a LIVE
    session let a new session inherit a closed one's queue, which is the very
    cross-session drain inbox_addresses() refuses to perform. Guarded by
    _counter_lock() so two sessions started at nearly the same instant cannot both
    read the same starting value and hand out the same ordinal; on a platform where
    that lock is unavailable this degrades to the same race as before.
    """
    path = _global_path()
    os.makedirs(global_dir(), exist_ok=True)
    with _counter_lock():
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
    _counter_lock() with next_ordinal() so a concurrent seed and increment cannot
    interleave into a lost update.
    """
    high = 0
    for rec in session_records().values():
        match = ORDINAL_SUFFIX_RE.match(agent_name(rec.get("agent_id") or ""))
        if match:
            high = max(high, int(match.group("ordinal")))
    if high:
        path = _global_path()
        os.makedirs(global_dir(), exist_ok=True)
        with _counter_lock():
            record = _read_json(path) or {}
            if (record.get("session_counter") or 0) < high:
                record["session_counter"] = high
                _write_json(path, record)
    return high


def save_fingerprint(fp):
    """Cache the gate's key fingerprint so crypto-free callers can build full ids."""
    if not (isinstance(fp, str) and FINGERPRINT_RE.match(fp)):
        return None
    path = _global_path()
    record = _read_json(path) or {}
    if record.get("fingerprint") == fp:
        return fp
    os.makedirs(global_dir(), exist_ok=True)
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
    tmp = path + ".tmp"
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
    record = {"agent_id": agent_id, "confirmed": bool(confirmed)}
    # The fingerprint is cached here for crypto-free readers; a rename must not drop
    # it or the hook loses the ability to build qualified ids.
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
        _ensure_git_excluded(base_dir)
        path = _identity_path(base_dir)
        return _write_identity(path, canonical, previous=_read_json(path))

    project_path = _identity_path(base_dir)
    project_record = _read_json(project_path)
    path = _global_path()
    os.makedirs(global_dir(), exist_ok=True)
    previous = _read_json(path) or (project_record if drop_project_override else None)
    _write_identity(path, canonical, previous=previous)

    if drop_project_override and project_record:
        # Global write first: a failed unlink leaves us un-consolidated, not id-less.
        try:
            os.unlink(project_path)
        except OSError:
            pass
    return canonical


def mark_confirmed(base_dir):
    """Keep the current id but stop prompting for it. Marks the file in force."""
    for path in (_identity_path(base_dir), _global_path()):
        data = _read_json(path)
        if not (data and data.get("agent_id")):
            continue
        if not data.get("confirmed"):
            data["confirmed"] = True
            _write_json(path, data)
        return data["agent_id"]
    return None


def _generate_and_persist():
    os.makedirs(global_dir(), exist_ok=True)
    path = _global_path()
    candidate = suggest_agent_id(scope="global")
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
