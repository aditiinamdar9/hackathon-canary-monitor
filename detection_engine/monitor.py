#!/usr/bin/env python3
"""
detection_engine/monitor.py

Watches the canary directory with watchdog, confirms real tampering by
re-hashing against manifest.json, resolves the responsible PID, and appends
confirmed events to events.jsonl.

Usage:
    python monitor.py --canary-dir ../canaries --manifest ../manifest.json
"""

import argparse
import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

try:
    import psutil
except ImportError:
    psutil = None  # /proc scan still works on Linux without it


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def sha256_file(path: str, chunk_size: int = 65536) -> str | None:
    """Hash a file; return None if it vanished or is unreadable."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(chunk_size):
                h.update(chunk)
        return h.hexdigest()
    except (FileNotFoundError, PermissionError, OSError):
        return None


def load_manifest(manifest_path: str) -> dict:
    """
    Load manifest.json from Part 1.

    Accepts either:
        { "/abs/path": "hexdigest", ... }
    or
        { "/abs/path": {"sha256": "hexdigest", "inode": 12345, ...}, ... }

    Normalizes to { resolved_path: {"sha256": ..., "inode": ...} }.
    """
    with open(manifest_path) as f:
        raw = json.load(f)

    manifest = {}
    for path, entry in raw.items():
        resolved = str(Path(path).resolve())
        if isinstance(entry, str):
            manifest[resolved] = {"sha256": entry, "inode": None}
        else:
            manifest[resolved] = {
                "sha256": entry.get("sha256") or entry.get("hash"),
                "inode": entry.get("inode"),
            }
    return manifest


# --------------------------------------------------------------------------
# PID resolution — must run FAST, before the offender closes the handle
# --------------------------------------------------------------------------

def find_pids_via_proc(target_path: str, target_inode: int | None) -> list[dict]:
    """
    Scan /proc/*/fd symlinks for handles pointing at our file.

    Matches by resolved path AND by inode (inode survives renames, and
    deleted-but-open files show up as '/path (deleted)' whose stat still
    reports the original inode).
    """
    hits = []
    my_pid = os.getpid()
    for pid_dir in os.scandir("/proc"):
        if not pid_dir.name.isdigit():
            continue
        pid = int(pid_dir.name)
        if pid == my_pid:
            continue
        fd_dir = f"/proc/{pid}/fd"
        try:
            fds = os.listdir(fd_dir)
        except (PermissionError, FileNotFoundError):
            continue
        for fd in fds:
            fd_path = os.path.join(fd_dir, fd)
            try:
                link = os.readlink(fd_path)
            except OSError:
                continue

            matched = False
            if link.split(" (deleted)")[0] == target_path:
                matched = True
            elif target_inode is not None:
                try:
                    if os.stat(fd_path).st_ino == target_inode:
                        matched = True
                except OSError:
                    pass

            if matched:
                try:
                    with open(f"/proc/{pid}/comm") as f:
                        name = f.read().strip()
                except OSError:
                    name = "?"
                try:
                    with open(f"/proc/{pid}/cmdline", "rb") as f:
                        cmdline = f.read().replace(b"\x00", b" ").decode(errors="replace").strip()
                except OSError:
                    cmdline = ""
                hits.append({"pid": pid, "name": name, "cmdline": cmdline, "fd": fd})
                break  # one hit per process is enough
    return hits


def find_pids_via_psutil(target_path: str) -> list[dict]:
    """Cross-platform fallback using psutil's open_files()."""
    if psutil is None:
        return []
    hits = []
    for proc in psutil.process_iter(["pid", "name", "open_files"]):
        try:
            for of in proc.info["open_files"] or []:
                if str(Path(of.path).resolve()) == target_path:
                    hits.append({
                        "pid": proc.info["pid"],
                        "name": proc.info["name"],
                        "cmdline": " ".join(proc.cmdline()),
                        "fd": getattr(of, "fd", None),
                    })
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return hits


def resolve_pids(target_path: str, target_inode: int | None,
                 attempts: int = 20, interval: float = 0.01) -> list[dict]:
    """
    Poll aggressively: file handles from a quick write/delete close within
    milliseconds, so hammer /proc for ~200ms before giving up.
    """
    use_proc = os.path.isdir("/proc")
    for _ in range(attempts):
        hits = (find_pids_via_proc(target_path, target_inode) if use_proc
                else find_pids_via_psutil(target_path))
        if hits:
            return hits
        time.sleep(interval)
    return []


# --------------------------------------------------------------------------
# Event handler
# --------------------------------------------------------------------------

class CanaryHandler(FileSystemEventHandler):
    def __init__(self, manifest: dict, events_log: str):
        super().__init__()
        self.manifest = manifest
        self.events_log = events_log
        # small debounce cache: (path, verdict_hash) -> last_seen ts
        self._recent: dict[tuple, float] = {}
        self._debounce_secs = 1.0

    # Route every event type through one pipeline
    def on_modified(self, event):
        self._handle(event, "modified")

    def on_created(self, event):
        self._handle(event, "created")

    def on_deleted(self, event):
        self._handle(event, "deleted")

    def on_moved(self, event):
        self._handle(event, "moved")

    def _handle(self, event, action: str):
        if event.is_directory:
            return

        path = str(Path(event.src_path).resolve())
        entry = self.manifest.get(path)
        if entry is None:
            # A brand-new file appearing inside the canary dir (e.g. a ransom
            # note) is suspicious too, but not a manifest canary — skip or log
            # as you prefer. Skipping keeps this part focused.
            return
        dest = getattr(event, "dest_path", None)
        dest = str(Path(dest).resolve()) if dest else None

        # 1) Hash FIRST. Takes milliseconds, and it's the evidence that
        #    confirms tampering. On macOS psutil.open_files() can take
        #    seconds per call, and by the time it returns the attacker has
        #    often renamed the file away — losing the hash AND the PID.
        expected = entry["sha256"]
        current_hash = sha256_file(dest) if dest else sha256_file(path)

        # 2) Then chase the PID with whatever time is left.
        pids = resolve_pids(path, entry.get("inode"))

        if action == "moved" and dest:
            reason = f"renamed to {Path(dest).name}"
        elif action == "deleted" or current_hash is None:
            reason = "file deleted or unreadable"
        elif current_hash != expected:
            reason = "hash mismatch"
        else:
            return

        # Debounce duplicate events (editors/ransomware often fire
        # modify+modify+close in a burst for one logical write).
        key = (path, current_hash)
        now = time.monotonic()
        if now - self._recent.get(key, 0) < self._debounce_secs:
            return
        self._recent[key] = now

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "path": path,
            "expected_sha256": expected,
            "observed_sha256": current_hash,
            "reason": reason,
            "suspect_processes": pids,   # may be [] if the handle closed first
            "dest_path": dest
        }
        self._append_event(record)

        # Handy single line to set a breakpoint on while debugging:
        print(f"[TAMPER] {action} {path} -> {len(pids)} suspect(s)")  # <-- breakpoint here

    def _append_event(self, record: dict):
        with open(self.events_log, "a") as f:
            f.write(json.dumps(record) + "\n")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Canary file tamper monitor")
    ap.add_argument("--canary-dir", required=True, help="Directory of canary files")
    ap.add_argument("--manifest", default="manifest.json", help="Manifest from Part 1")
    ap.add_argument("--events-log", default="events.jsonl", help="Output JSONL log")
    args = ap.parse_args()

    canary_dir = str(Path(args.canary_dir).resolve())
    manifest = load_manifest(args.manifest)

    handler = CanaryHandler(manifest, args.events_log)
    observer = Observer()
    observer.schedule(handler, canary_dir, recursive=True)
    observer.start()
    print(f"Watching {canary_dir} ({len(manifest)} canaries in manifest). Ctrl-C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()