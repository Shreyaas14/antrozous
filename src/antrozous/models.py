"""
data types
"""

from typing import Optional
from pydantic import BaseModel
from datetime import datetime


class Attachment(BaseModel):
    sha256: str
    mime: str
    size: int


class Message(BaseModel):
    """v1 carries `content` in the clear; v2 seals it.

    In v2 the sender's text, the user names and the attachment refs all live inside
    `ciphertext`, which only the recipient can open. The relay keeps just what it
    needs to route: from_agent, to_agent and a timestamp.
    """

    v: int = 1
    from_agent: str
    to_agent: str
    timestamp: datetime

    # v1 fields (empty on v2)
    from_user: str = ""
    to_user: str = ""
    content: str = ""
    attachments: list[Attachment] = []

    # v2 fields
    ciphertext: Optional[str] = None
    signature: Optional[str] = None
    sender_ed25519: Optional[str] = None


class KeyBundle(BaseModel):
    """Public half of a device's keys.

    `signature` is only needed to ROTATE an already-registered x25519 key: it is an
    Ed25519 signature by the registered identity key over keyreg_bytes(). First
    registration needs none, and a changed ed25519 is refused outright.
    """

    ed25519: str
    x25519: str
    signature: Optional[str] = None
