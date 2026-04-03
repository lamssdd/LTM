#!/usr/bin/env python3
"""Quick test script to verify JSON output from recon agents."""
import json
import sys
sys.path.insert(0, '.')

from agents.passive_recon_agent import PassiveReconAgent
from agents.active_recon_agent import ActiveReconAgent

target = 'http://testfire.net/'

def log(msg, lvl='info'):
    print(f'[{lvl.upper():8}] {msg}')

# Test Passive Recon
print('=' * 70)
print('PASSIVE RECON SCAN')
print('=' * 70)
passive = PassiveReconAgent(log_callback=log)
passive_result = passive.execute(target, {})

print()
print('=' * 70)
print('PASSIVE RESULT JSON:')
print('=' * 70)
print(json.dumps(passive_result, indent=2, default=str))

# Test Active Recon
print()
print('=' * 70)
print('ACTIVE RECON SCAN')
print('=' * 70)
active = ActiveReconAgent(log_callback=log)
active_result = active.execute(target, {"passive_result": passive_result})

print()
print('=' * 70)
print('ACTIVE RESULT JSON:')
print('=' * 70)
print(json.dumps(active_result, indent=2, default=str))
