#!/usr/bin/env python3
"""
mock_ransomware.py

This is a PRETEND attacker for TESTING ONLY. It does not encrypt anything
or spread anywhere. It just scribbles junk over the decoy canary files so
your monitor.py notices the change and logs a tamper event.

Run this in a SECOND terminal while monitor.py is already watching.
"""

import time
from pathlib import Path

canary_dir = Path("canaries")
targets = list(canary_dir.glob("*"))

print(f"Pretend-attacking {len(targets)} files...")
for f in targets:
    # Overwrite the file's contents with obvious junk.
    f.write_text("!!! TAMPERED BY MOCK TEST !!!\n")
    print(f"  scribbled on {f.name}")
    time.sleep(0.3)  # small pause so each hit is easy to see

print("Done. Check your monitor's terminal and events.jsonl")
