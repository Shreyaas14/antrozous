"""
All of the data types used in Antrozous. 
"""

from datetime import datetime
from pydantic import BaseModel
from enum import Enum

## Enums
class AgentSessionType(Enum):
  SHORT_TERM = 1 # claude code session, codex session, grok build session, terminal hermes agent, etc. 
  LONG_RUNNING = 2 # telegram agent, etc. 


class UserKeypair(BaseModel):
  private_key: str # encoded hex strings for now
  public_key: str 

class SessionKeypair(BaseModel):
  private_key: str
  public_key: str 

class Certificate(BaseModel):
  user_pubkey: str
  session_pubkey: str 
  timestamp: datetime
  signature: str # encoded string?
  agent_session: AgentSessionType

class Message(BaseModel):
  content: str #json

class EncryptedMessage(BaseModel):
  message_content: Message
  certificate: Certificate

class NostrEvent(BaseModel):
  pass 
