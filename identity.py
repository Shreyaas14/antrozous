import os
import json
import secrets
import subprocess

from datetime import datetime

GIT_EXCLUDE_PATTERN = ".antrozous/"

def _identity_path(base_dir):
    return os.path.join(base_dir, ".antrozous", "identity.json")

def _read_json(filename: str):
    try:
      with open(filename, 'r') as file:
          data = json.load(file)
          return data
    except (FileNotFoundError, json.JSONDecodeError):
          return None


def _ensure_git_excluded(base_dir):
    """Keep per-project identity state out of Git without editing tracked files."""
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
        # Identity must still work outside Git repos or when Git is unavailable.
        pass
    
def _generate_and_persist(base_dir):
    d = os.path.join(base_dir, ".antrozous")
    os.makedirs(d, exist_ok=True)
    path = _identity_path(base_dir)
    candidate = "agent-" + secrets.token_hex(5)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY) # need to test this at scale
        with os.fdopen(fd, "w") as f:
            json.dump({"agent_id": candidate, "created_at": str(datetime.now())}, f)
        return candidate
    except FileExistsError:
        data = _read_json(path)
        return data["agent_id"]
    
def find_directory():
  return os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    
def resolve_agent_id(base_dir):
    v = os.environ.get("AGENT_ID", "")
    if v.strip():
        return v.strip()
    _ensure_git_excluded(base_dir)
    data = _read_json(_identity_path(base_dir))
    if data and data.get("agent_id"):
        return data["agent_id"]
    return _generate_and_persist(base_dir)
