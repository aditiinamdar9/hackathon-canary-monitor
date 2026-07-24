#!/usr/bin/env python3
"""
setup_test.py

Makes a pretend "canary" folder with a few decoy files, then writes a
manifest.json listing each file's SHA-256 hash and inode number.
Run this ONCE before testing monitor.py.
"""

import hashlib
import json
import os
from pathlib import Path

# 1. Make a folder to hold the fake important-looking files.
canary_dir = Path("canaries")
canary_dir.mkdir(exist_ok=True)

# 2. Create a few decoy files with believable names.
files = {
    "passwords.txt": "gmail: hunter2\nbank: correct-horse\n",
    "budget_2026.csv": "month,total\nJan,4200\nFeb,3980\n",
    "secret_recipe.txt": "Grandma's cookies: add 2x the butter.\n",
}
for name, content in files.items():
    (canary_dir / name).write_text(content)

# 3. Record each file's fingerprint (hash) and inode into manifest.json.
manifest = {}
for name in files:
    path = canary_dir / name
    resolved = str(path.resolve())
    manifest[resolved] = {
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "inode": os.stat(path).st_ino,
    }

Path("manifest.json").write_text(json.dumps(manifest, indent=2))

print(f"Created {len(files)} canary files in ./{canary_dir}/")
print("Wrote manifest.json")
print("\nNow you're ready to test. See the numbered steps.")
