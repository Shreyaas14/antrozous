"""
FastAPI server to store messages.
"""

## imports
import json 
import os 

from typing import List, Dict
from fastapi import FastAPI

from .models import Message

app = FastAPI(title="Agent Message Relay")

inboxes: Dict[str, List[dict]] = {}

BACKUP_FILE = "messages.json"
if os.path.exists(BACKUP_FILE):
  with open(BACKUP_FILE) as f:
    inboxes = json.load(f)

@app.post("/send")
def send_message(msg: Message):
  if msg.to_agent not in inboxes:
    inboxes[msg.to_agent] = []
    inboxes[msg.to_agent].append(msg.model_dump())
    return { "status": "sent" }

@app.get("/inbox/{agent_id}")
def get_inbox(agent_id: str):
  return inboxes.get(agent_id, [])


