import os
import json
import secrets

from datetime import datetime

IDENTITY_PATH = "./.antrozous/identity.json"

def _identity_path(base_dir):
    return os.path.join(base_dir, ".antrozous", "identity.json")

def _read_json(filename: str):
    try:
      with open(filename, 'r') as file:
          data = json.load(file)
          return data
    except (FileNotFoundError, json.JSONDecodeError):
          return None
    
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
    data = _read_json(_identity_path(base_dir))
    if data and data.get("agent_id"):
        return data["agent_id"]
    return _generate_and_persist(base_dir)