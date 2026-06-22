"""
FastAPI server to store messages (the relay).

Agents POST messages to /send; recipients pull them with GET /inbox/{agent_id}
and clear what they've handled with POST /inbox/{agent_id}/consume.

In-memory store for now (MVP). The relay must stay running for the duration of a
test; persistence is a follow-up (see RUNBOOK.md).
"""

## imports
import json
import os

from typing import List, Dict
from fastapi import FastAPI

from .models import Message

app = FastAPI(title="Agent Message Relay")

# agent_id -> list of message dicts (JSON-safe, timestamp as ISO string)
inboxes: Dict[str, List[dict]] = {}

BACKUP_FILE = "messages.json"
if os.path.exists(BACKUP_FILE):
  with open(BACKUP_FILE) as f:
    inboxes = json.load(f)


@app.get("/health")
def health():
  return {"status": "ok", "agents": list(inboxes.keys())}


@app.post("/send")
def send_message(msg: Message):
  if msg.to_agent not in inboxes:
    inboxes[msg.to_agent] = []
  # mode="json" keeps the datetime as an ISO string so the store stays JSON-safe.
  inboxes[msg.to_agent].append(msg.model_dump(mode="json"))
  return {"status": "sent", "pending": len(inboxes[msg.to_agent])}


@app.get("/inbox/{agent_id}")
def get_inbox(agent_id: str):
  # Non-destructive read: returns the pending messages without clearing them.
  return inboxes.get(agent_id, [])


@app.post("/inbox/{agent_id}/consume")
def consume_inbox(agent_id: str, count: int = -1):
  """Remove and return the oldest `count` messages (all if count<0).

  The receiver calls this AFTER it has handled a batch, so the same messages
  aren't shown again on the next check. Note (MVP): messages that arrive between
  a GET and this consume are not returned here — acceptable for the manual demo.
  """
  pending = inboxes.get(agent_id, [])
  n = len(pending) if count < 0 else min(count, len(pending))
  taken, inboxes[agent_id] = pending[:n], pending[n:]
  return {"consumed": taken, "remaining": len(inboxes[agent_id])}
