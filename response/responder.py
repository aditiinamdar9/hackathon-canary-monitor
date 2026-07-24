#!/usr/bin/env python3

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


def load_whitelist(path=WHITELIST_PATH):
    if not path.exists():
        print(f"[responder] ERROR: whitelist not found at {path}")
        sys.exit(1)

    try:
        with open(path, "r") as file:
            data = json.load(file)
    except (OSError, json.JSONDecodeError) as error:
        print(f"[responder] ERROR: could not load whitelist: {error}")
        sys.exit(1)

    return {
        "protected_names": set(data.get("protected_names", [])),
        "protected_cmdline_substrings":
            data.get("protected_exact_cmdline_substrings", []),
        "protected_pids": set(data.get("protected_pids", []))
    }


def get_process_info(pid):
    if not isinstance(pid, int) or pid <= 0:
        return None, None, False

    if HAVE_PSUTIL:
        try:
            process = psutil.Process(pid)
            name = process.name()
            cmdline = " ".join(process.cmdline())
            return name, cmdline, True
        except psutil.NoSuchProcess:
            return None, None, False
        except psutil.AccessDenied:
            return "<access-denied>", "<access-denied>", True

    try:
        os.kill(pid, 0)
        return None, None, True
    except ProcessLookupError:
        return None, None, False
    except PermissionError:
        return "<access-denied>", "<access-denied>", True


def is_whitelisted(pid, name, cmdline, whitelist):
    if pid in whitelist["protected_pids"]:
        return True, f"PID {pid} is protected"

    if name and name in whitelist["protected_names"]:
        return True, f"process name '{name}' is protected"

    if cmdline:
        for protected_text in whitelist["protected_cmdline_substrings"]:
            if protected_text in cmdline:
                return True, (
                    f"command line contains protected text "
                    f"'{protected_text}'"
                )

    return False, None


def confirm_stopped(pid, timeout=1.0):
    deadline = time.time() + timeout

    while time.time() < deadline:
        if HAVE_PSUTIL:
            try:
                process = psutil.Process(pid)

                if process.status() == psutil.STATUS_STOPPED:
                    return True
            except psutil.NoSuchProcess:
                return False
            except psutil.AccessDenied:
                return False
        else:
            try:
                output = os.popen(
                    f"ps -o stat= -p {pid}"
                ).read().strip()

                if output.startswith("T"):
                    return True
            except Exception:
                return False

        time.sleep(0.05)

    return False


def freeze_pid(pid, expected_name=None):
    name, cmdline, exists = get_process_info(pid)

    if not exists:
        return {
            "success": False,
            "reason": "process does not exist",
            "pid": pid
        }

    if expected_name and name and expected_name != name:
        return {
            "success": False,
            "reason": (
                f"PID identity changed from '{expected_name}' "
                f"to '{name}'"
            ),
            "pid": pid
        }

    try:
        os.kill(pid, signal.SIGSTOP)
    except ProcessLookupError:
        return {
            "success": False,
            "reason": "process exited before SIGSTOP was sent",
            "pid": pid
        }
    except PermissionError:
        return {
            "success": False,
            "reason": "permission denied",
            "pid": pid
        }
    except OSError as error:
        return {
            "success": False,
            "reason": f"operating system error: {error}",
            "pid": pid
        }

    stopped = confirm_stopped(pid)

    if stopped:
        reason = "SIGSTOP sent and stopped state confirmed"
    else:
        reason = "SIGSTOP sent, but stopped state could not be confirmed"

    return {
        "success": True,
        "reason": reason,
        "pid": pid,
        "process_name": name,
        "cmdline": cmdline
    }


def append_outcome(event, outcome):
    record = {
        "correlated_event": {
            "path": event.get("path"),
            "pid": outcome.get("pid"),
            "timestamp": event.get("timestamp"),
            "action": event.get("action")
        },
        "response": {
            "action": (
                "freeze"
                if outcome["success"]
                else "freeze_attempt_failed"
            ),
            "success": outcome["success"],
            "reason": outcome["reason"],
            "pid": outcome["pid"],
            "process_name": outcome.get("process_name"),
            "cmdline": outcome.get("cmdline"),
            "responded_at": datetime.now(timezone.utc).isoformat()
        }
    }

    INCIDENTS_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    with open(INCIDENTS_LOG_PATH, "a") as file:
        file.write(json.dumps(record) + "\n")

    return record


def get_event_pids(event):
    pids = []

    single_pid = event.get("pid")

    if isinstance(single_pid, int):
        pids.append(single_pid)

    suspect_processes = event.get("suspect_processes", [])

    if isinstance(suspect_processes, list):
        for pid in suspect_processes:
            if isinstance(pid, int) and pid not in pids:
                pids.append(pid)

    return pids


def handle_event(event, whitelist):
    raw_processes = event.get("suspect_processes", [])

    if event.get("pid") is not None:
        raw_processes = [event.get("pid")] + raw_processes

    if not raw_processes:
        print(
            f"[responder] No suspect processes found for event: "
            f"{event.get('path')}"
        )
        return

    processed_pids = set()

    for process_entry in raw_processes:
        expected_name = None

        if isinstance(process_entry, dict):
            pid = process_entry.get("pid")
            expected_name = process_entry.get("name")
        else:
            pid = process_entry

        if not isinstance(pid, int):
            print(
                f"[responder] skipping invalid process entry: "
                f"{process_entry}"
            )
            continue

        if pid in processed_pids:
            continue

        processed_pids.add(pid)

        name, cmdline, exists = get_process_info(pid)

        if not exists:
            outcome = {
                "success": False,
                "reason": "process does not exist",
                "pid": pid
            }

            append_outcome(event, outcome)
            print(f"[responder] PID {pid} no longer exists")
            continue

        whitelisted, reason = is_whitelisted(
            pid,
            name,
            cmdline,
            whitelist
        )

        if whitelisted:
            print(
                f"[responder] SKIPPING PID {pid} -- "
                f"whitelisted ({reason})"
            )

            outcome = {
                "success": False,
                "reason": f"whitelisted: {reason}",
                "pid": pid,
                "process_name": name,
                "cmdline": cmdline
            }

            append_outcome(event, outcome)
            continue

        if expected_name is None:
            expected_name = name

        print(f"[responder] freezing PID {pid} ({name}) ...")

        outcome = freeze_pid(
            pid,
            expected_name=expected_name
        )

        append_outcome(event, outcome)

        if outcome["success"]:
            print(
                f"[responder] FROZEN PID {pid}: "
                f"{outcome['reason']}"
            )
        else:
            print(
                f"[responder] did NOT freeze PID {pid}: "
                f"{outcome['reason']}"
            )


def tail_events(path, whitelist):
    print(f"[responder] watching {path}")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)

    with open(path, "r") as file:
        file.seek(0, os.SEEK_END)

        while True:
            line = file.readline()

            if not line:
                time.sleep(POLL_INTERVAL_SEC)
                continue

            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                print(
                    f"[responder] skipping malformed JSON: {line}"
                )
                continue

            handle_event(event, whitelist)


def main():
    parser = argparse.ArgumentParser(
        description="Canary response and mitigation engine"
    )

    parser.add_argument(
        "--pid",
        type=int,
        help="Manually test freezing one PID"
    )

    parser.add_argument(
        "--events",
        type=Path,
        default=EVENTS_PATH,
        help="Path to events.jsonl"
    )

    args = parser.parse_args()
    whitelist = load_whitelist()

    if args.pid is not None:
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "manual_test",
            "path": None,
            "pid": args.pid
        }

        handle_event(event, whitelist)
        return

    try:
        tail_events(args.events, whitelist)
    except KeyboardInterrupt:
        print("\n[responder] stopped")


if __name__ == "__main__":
    main()