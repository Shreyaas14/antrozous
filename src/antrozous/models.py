"""
data types
"""

from pydantic import BaseModel
from datetime import datetime 

class Message(BaseModel):
  from_agent: str 
  from_user: str
  to_agent: str 
  to_user: str
  content: str 
  timestamp: datetime 


