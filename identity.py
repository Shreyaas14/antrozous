import os
import re
import json
import secrets
import subprocess

from datetime import datetime

GIT_EXCLUDE_PATTERN = ".antrozous/"

# Ids are interpolated unescaped into /inbox/<id> and /ws/<id>.
AGENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}[a-z0-9]$")


def global_dir():
    return os.environ.get("ANTROZOUS_HOME") or os.path.expanduser("~/.antrozous")


def _global_path():
    return os.path.join(global_dir(), "identity.json")


def sessions_dir():
    return os.path.join(global_dir(), "sessions")


def _session_path(pid=None):
    return os.path.join(sessions_dir(), "%d.json" % (pid or os.getpid()))


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


def live_sessions():
    """{pid: agent_id} for sessions still running. Prunes dead entries."""
    out = {}
    try:
        names = os.listdir(sessions_dir())
    except OSError:
        return out
    for name in names:
        if not name.endswith(".json"):
            continue
        try:
            pid = int(name[:-5])
        except ValueError:
            continue
        path = os.path.join(sessions_dir(), name)
        if not _pid_alive(pid):
            try:
                os.unlink(path)
            except OSError:
                pass
            continue
        data = _read_json(path)
        if data and data.get("agent_id"):
            out[pid] = data["agent_id"]
    return out


def register_session(agent_id):
    os.makedirs(sessions_dir(), exist_ok=True)
    _write_json(
        _session_path(),
        {"agent_id": agent_id, "pid": os.getpid(), "started_at": str(datetime.now())},
    )
    return agent_id


def unregister_session():
    try:
        os.unlink(_session_path())
    except OSError:
        pass


def suggest_session_id(base):
    """base if no live session holds it, else base-2, base-3, …"""
    taken = set(live_sessions().values())
    if base not in taken:
        return base
    for n in range(2, 100):
        candidate = normalize_agent_id("%s-%d" % (base, n))
        if candidate and candidate not in taken:
            return candidate
    return normalize_agent_id("%s-%s" % (base, secrets.token_hex(2))) or base


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
