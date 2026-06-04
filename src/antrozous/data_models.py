"""
All of the data types used in Antrozous. 
"""

from datetime import datetime
from pydantic import BaseModel
from typing import List
from enum import Enum

## Enums
class AgentSessionType(Enum):
  SHORT_TERM = 1 # claude code session, codex session, grok build session, terminal hermes agent, etc. 
  LONG_RUNNING = 2 # telegram agent, etc. 


class UserKeypair(BaseModel):
  private_key: str # encoded hex string
  public_key: str 

class SessionKeypair(BaseModel):
  private_key: str
  public_key: str 

class Certificate(BaseModel):
  user_pubkey: str
  session_pubkey: str 
  created_at: datetime
  signature: str # encoded hex string

class Message(BaseModel):
  content: str #json

class EncryptedMessage(BaseModel):
  session_pubkey: str
  user_pubkey: str
  ciphertext: str # encrypted message
  certificate: Certificate
  agent_session: AgentSessionType
  signature: str

class NostrEvent(BaseModel):
  kind: int # type of event
  content: str # encrypted message as a JSON
  tags: List[List]
  created_at: datetime
  signature: str
  id: str # hex string 
  public_key: str # session pubkey 
