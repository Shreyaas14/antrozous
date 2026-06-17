"""
Functions needed for:
- data encryption
- data decryption
- keypair signing
- certificate generation
"""

import io 
import json 

from datetime import datetime
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def generate_keypair():
  priv_key = Ed25519PrivateKey.generate()
  pub_key = priv_key.public_key()

  return priv_key, pub_key

def master_keypair():
  master_priv_key, master_pub_key = generate_keypair()
  return master_priv_key, master_pub_key

def session_keypair():
  session_priv_key, session_pub_key = generate_keypair()
  return session_priv_key, session_pub_key

def create_and_sign_certificate(
    master_priv_key: Ed25519PrivateKey,
    master_pub_key: str, 
    session_pub_key: str):
  created_at = datetime.now() # might need to switch to utc later

  data = {"master_pubkey": master_pub_key, "session_pubkey": session_pub_key, "created_at": created_at}

  try:
    b_data = io.BytesIO(json.dumps(data).encode('utf-8'))
    signed = master_priv_key.sign(b_data.getvalue())

    return signed
  except Exception as error:
    print(f"Error occurred while signing certificate: {error}")  

def encrypt():
  pass 

def decrypt():
  pass 

def publish_to_relay():
  pass 

def fetch_from_relay():
  pass