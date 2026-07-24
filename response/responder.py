#!/usr/bin/env python3
"""
responder.py -- Part 4: Response / Mitigation

Tails events.jsonl (written by the detection engine in Part 2 / relayed by
Part 3's listener), and for each confirmed-tamper event:

  1. Looks up the responsible PID.
  2. Checks it against whitelist.json (name / cmdline / hardcoded floor pids).
     If it matches the whitelist, we NEVER touch it -- log and skip instead.
  3. Re-verifies the PID is still alive and still looks like the process the
     detector saw (best-effort defense against PID-reuse races).
  4. Freezes it with SIGSTOP (reversible -- use SIGCONT to resume, e.g. for
     inspection). We deliberately do NOT use SIGKILL for the sim.
  5. Appends an outcome record to incidents.log so Part 3's alert entries and
     Part 4's response outcomes live in one auditable trail.

Also usable directly for manual testing:
    python3 responder.py --pid 12345
"""

import argparse
import json
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import psutil
    HAVE_PSUTIL = True
except ImportError:
    HAVE_PSUTIL = False

BASE_DIR = Path(__file__).resolve().parent
EVENTS_PATH = BASE_DIR.parent / "detection_engine" / "events.jsonl"
WHITELIST_PATH = BASE_DIR / "whitelist.json"
INCIDENTS_LOG_PATH = BASE_DIR.parent / "alerting" / "incidents.log"

POLL_INTERVAL_SEC = 0.25


# --------------------------------------------------------------------------- #
# Whitelist
# --------------------------------------------------------------------------- #

def load_whitelist(path=WHITELIST_PATH):
    if not path.exists():
        print(f"[responder] WARNING: no whitelist found at {path}. "
              f"Refusing to run without one -- create whitelist.json first.")
        sys.exit(1)
    with open(path) as f:
        wl = json.load(f)
    return {
        "protected_names": set(wl.get("protected_names", [])),
        "protected_cmdline_substrings": wl.get("protected_exact_cmdline_substrings", []),
        "protected_pids": set(wl.get("protected_pids", [])),
    }


def get_process_info(pid):
    """Return (name, cmdline_str, exists) for a pid, best-effort."""
    if HAVE_PSUTIL:
        try:
            p = psutil.Process(pid)
            name = p.name()
            cmdline = " ".join(p.cmdline())
            return name, cmdline, True
        except psutil.NoSuchProcess:
            return None, None, False
        except psutil.AccessDenied:
            return "<access-denied>", "<access-denied>", True
    # Fallback: /proc
    proc_path = Path(f"/proc/{pid}")
    if not proc_path.exists():
        return None, None, False
    try:
        name = (proc_path / "comm").read_text().strip()
    except Exception:
        name = None
    try:
        cmdline = (proc_path / "cmdline").read_bytes().replace(b"\x00", b" ").decode(errors="replace").strip()
    except Exception:
        cmdline = None
    return name, cmdline, True


def is_whitelisted(pid, name, cmdline, whitelist):
    if pid in whitelist["protected_pids"]:
        return True, f"pid {pid} is in protected_pids"
    if name and name in whitelist["protected_names"]:
        return True, f"process name '{name}' is in protected_names"
    if cmdline:
        for substr in whitelist["protected_cmdline_substrings"]:
            if substr in cmdline:
                return True, f"cmdline contains protected substring '{substr}'"
    return False, None


# --------------------------------------------------------------------------- #
# Freeze / outcome
# --------------------------------------------------------------------------- #

def freeze_pid(pid, expected_name=None):
    """
    Attempts to SIGSTOP the pid. Returns a dict describing the outcome.
    Re-checks liveness/identity right before signaling to shrink the
    PID-reuse race window as much as possible in a non-atomic world.
    """
    name, cmdline, exists = get_process_info(pid)

    if not exists:
        return {
            "success": False,
            "reason": "process no longer exists (likely exited before we could act)",
            "pid": pid,
        }

    if expected_name and name and expected_name != name:
        return {
            "success": False,
            "reason": (f"PID {pid} identity mismatch: detector saw '{expected_name}', "
                       f"now this pid is '{name}'. Likely PID reuse -- refusing to act."),
            "pid": pid,
        }

    try:
        os.kill(pid, signal.SIGSTOP)
    except ProcessLookupError:
        return {"success": False, "reason": "process exited during freeze attempt", "pid": pid}
    except PermissionError:
        return {"success": False, "reason": "permission denied (need same-user or root)", "pid": pid}
    except Exception as e:
        return {"success": False, "reason": f"unexpected error: {e}", "pid": pid}

    # Confirm it actually stopped (best-effort; /proc/[pid]/stat state field).
    frozen_confirmed = _confirm_stopped(pid)

    return {
        "success": True,
        "reason": "SIGSTOP sent" + (" and confirmed (state=T)" if frozen_confirmed else " (state not confirmed)"),
        "pid": pid,
        "process_name": name,
        "cmdline": cmdline,
    }


def _confirm_stopped(pid, timeout=1.0):
    deadline = time.time() + timeout
    stat_path = Path(f"/proc/{pid}/stat")
    while time.time() < deadline:
        try:
            stat = stat_path.read_text()
            # Format: pid (comm) STATE ...
            state = stat.split(") ", 1)[1].split(" ", 1)[0]
            if state == "T":
                return True
        except Exception:
            return False
        time.sleep(0.05)
    return False


def append_outcome(event, outcome):
    """
    Appends a JSON line to incidents.log combining the original event with
    the response outcome, so Part 3's alert records and Part 4's mitigation
    records are traceable to the same incident.

    NOTE: coordinate the schema below with whoever wrote Part 3's
    incidents.log writer -- this assumes each line is a JSON object and that
    matching on (path, pid, detected_at) is enough to correlate. Adjust the
    correlation keys if Part 3 uses different field names.
    """
    record = {
        "correlated_event": {
            "path": event.get("path"),
            "suspect_processes": event.get("suspect_processes", []),
            "detected_at": event.get("timestamp"),
        },
        "response": {
            "action": "freeze" if outcome["success"] else "freeze_attempt_failed",
            "success": outcome["success"],
            "reason": outcome["reason"],
            "pid": outcome["pid"],
            "process_name": outcome.get("process_name"),
            "cmdline": outcome.get("cmdline"),
            "responded_at": datetime.now(timezone.utc).isoformat(),
        },
    }
    INCIDENTS_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(INCIDENTS_LOG_PATH, "a") as f:
        f.write(json.dumps(record) + "\n")
    return record


# --------------------------------------------------------------------------- #
# Tail events.jsonl
# --------------------------------------------------------------------------- #

def tail_events(path, whitelist):
    print(f"[responder] watching {path} ...")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)

    with open(path, "r") as f:
        f.seek(0, os.SEEK_END)  
        while True:
            line = f.readline()
            if not line:
                time.sleep(POLL_INTERVAL_SEC)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                print(f"[responder] skipping malformed line: {line!r}")
                continue
            handle_event(event, whitelist)


def handle_event(event, whitelist):
    pids = event.get("suspect_processes", [])

    if not pids:
        print(f"[responder] No suspect processes found for event: {event.get('path')}")
        return

    for pid in pids:
        detector_name, detector_cmdline, exists = get_process_info(pid)

        whitelisted, reason = is_whitelisted(
            pid,
            detector_name,
            detector_cmdline,
            whitelist
        )

        if whitelisted:
            print(f"[responder] SKIPPING pid {pid} -- whitelisted ({reason})")
            outcome = {
                "success": False,
                "reason": f"whitelisted: {reason}",
                "pid": pid
            }
            append_outcome(event, outcome)
            continue

        print(f"[responder] freezing pid {pid} ({detector_name}) ...")

        outcome = freeze_pid(
            pid,
            expected_name=detector_name
        )

        append_outcome(event, outcome)

        if outcome["success"]:
            print(f"[responder] FROZEN pid {pid}: {outcome['reason']}")
        else:
            print(f"[responder] did NOT freeze pid {pid}: {outcome['reason']}")

    detector_name, detector_cmdline, exists = get_process_info(pid)
    whitelisted, reason = is_whitelisted(pid, detector_name, detector_cmdline, whitelist)

    if whitelisted:
        print(f"[responder] SKIPPING pid {pid} -- whitelisted ({reason})")
        outcome = {"success": False, "reason": f"whitelisted: {reason}", "pid": pid}
        append_outcome(event, outcome)
        return

    print(f"[responder] freezing pid {pid} ({detector_name}) ...")
    outcome = freeze_pid(pid, expected_name=detector_name)
    append_outcome(event, outcome)

    if outcome["success"]:
        print(f"[responder] FROZEN pid {pid}: {outcome['reason']}")
    else:
        print(f"[responder] did NOT freeze pid {pid}: {outcome['reason']}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser(description="Canary response/mitigation engine")
    parser.add_argument("--pid", type=int, help="Manually freeze a single PID and exit (for testing).")
    parser.add_argument("--events", type=Path, default=EVENTS_PATH, help="Path to events.jsonl")
    args = parser.parse_args()

    whitelist = load_whitelist()

    if args.pid:
        name, cmdline, exists = get_process_info(args.pid)
        whitelisted, reason = is_whitelisted(args.pid, name, cmdline, whitelist)
        if whitelisted:
            print(f"[responder] refusing to freeze pid {args.pid}: whitelisted ({reason})")
            return
        outcome = freeze_pid(args.pid, expected_name=name)
        fake_event = {"pid": args.pid, "path": None, "detected_at": datetime.now(timezone.utc).isoformat()}
        append_outcome(fake_event, outcome)
        print(outcome)
        return

    try:
        tail_events(args.events, whitelist)
    except KeyboardInterrupt:
        print("\n[responder] stopped.")


if __name__ == "__main__":
    main()