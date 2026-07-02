"""
FastAPI server to store and relay messages.

HTTP (pull):
  POST /send                     store a message
  GET  /inbox/{agent_id}         list pending (non-destructive)
  POST /inbox/{agent_id}/consume clear handled messages

WebSocket (push):
  WS   /ws/{agent_id}            a recipient connects and receives a content-free
                                 DOORBELL whenever a message lands for it. The
                                 doorbell carries NO body and NO attacker-controlled
                                 strings — only a trigger + a pending count — so a
                                 client (Monitor / channel) can react and then pull
                                 the real content through the approval gate.

In-memory store (MVP); the relay must stay running for a session. Persistence is
a follow-up.
"""

import json
import os

from typing import List, Dict
from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from .models import Message

app = FastAPI(title="Agent Message Relay")

# agent_id -> list of message dicts (JSON-safe, timestamp as ISO string)
inboxes: Dict[str, List[dict]] = {}

BACKUP_FILE = "messages.json"
if os.path.exists(BACKUP_FILE):
  with open(BACKUP_FILE) as f:
    inboxes = json.load(f)


class ConnectionManager:
  """Tracks live WebSocket recipients per agent and pushes doorbells to them."""

  def __init__(self):
    self.active: Dict[str, List[WebSocket]] = {}

  async def connect(self, agent_id: str, ws: WebSocket):
    await ws.accept()
    self.active.setdefault(agent_id, []).append(ws)

  def disconnect(self, agent_id: str, ws: WebSocket):
    conns = self.active.get(agent_id)
    if conns and ws in conns:
      conns.remove(ws)

  async def doorbell(self, agent_id: str, payload: dict):
    dead = []
    for ws in list(self.active.get(agent_id, [])):
      try:
        await ws.send_text(json.dumps(payload))
      except Exception:
        dead.append(ws)
    for ws in dead:
      self.disconnect(agent_id, ws)

  def count(self, agent_id: str) -> int:
    return len(self.active.get(agent_id, []))


manager = ConnectionManager()


@app.get("/health")
def health():
  return {"status": "ok", "agents": list(inboxes.keys()),
          "ws_connections": {a: manager.count(a) for a in manager.active}}


@app.post("/send")
async def send_message(msg: Message):
  if msg.to_agent not in inboxes:
    inboxes[msg.to_agent] = []
  inboxes[msg.to_agent].append(msg.model_dump(mode="json"))
  n = len(inboxes[msg.to_agent])
  # DOORBELL: content-free trigger. NO body, NO sender string (both are
  # attacker-controlled) — only a fixed type and a numeric count. The recipient
  # reacts by pulling the real content through the check_inbox approval gate.
  await manager.doorbell(msg.to_agent, {"type": "doorbell", "pending": n})
  return {"status": "sent", "pending": n}


@app.get("/inbox/{agent_id}")
def get_inbox(agent_id: str):
  return inboxes.get(agent_id, [])


@app.post("/inbox/{agent_id}/consume")
def consume_inbox(agent_id: str, count: int = -1):
  """Remove and return the oldest `count` messages (all if count<0)."""
  pending = inboxes.get(agent_id, [])
  n = len(pending) if count < 0 else min(count, len(pending))
  taken, inboxes[agent_id] = pending[:n], pending[n:]
  return {"consumed": taken, "remaining": len(inboxes[agent_id])}


@app.websocket("/ws/{agent_id}")
async def ws_inbox(websocket: WebSocket, agent_id: str):
  """A recipient holds this open to get doorbells. On connect it gets one
  'connected' frame carrying the current pending count (so a client that
  reconnects doesn't miss a backlog); thereafter one doorbell per new message."""
  await manager.connect(agent_id, websocket)
  try:
    await websocket.send_text(json.dumps(
        {"type": "connected", "agent_id": agent_id,
         "pending": len(inboxes.get(agent_id, []))}))
    while True:
      # Keep the socket open. We don't require client input; any received text
      # (e.g. a keepalive ping) is simply ignored.
      await websocket.receive_text()
  except WebSocketDisconnect:
    manager.disconnect(agent_id, websocket)
  except Exception:
    manager.disconnect(agent_id, websocket)
