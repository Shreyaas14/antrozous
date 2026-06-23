"""
Script for now so you can use this from any directory. 
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import identity

if __name__ == "__main__": 
  agent_id =identity.resolve_agent_id(identity.find_directory())
  print(f"Your Agent ID: {agent_id}")


