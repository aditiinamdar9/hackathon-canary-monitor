import os
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SANDBOX_DIRECTORY = (PROJECT_ROOT / "sandbox").resolve()
DELAY = 2


def safe_path(file_path):
    resolved_path = file_path.resolve()

    if not resolved_path.is_relative_to(SANDBOX_DIRECTORY):
        raise ValueError(f"Unsafe path blocked: {resolved_path}")

    return resolved_path


def simulate_ransomware():
    if not SANDBOX_DIRECTORY.exists():
        raise FileNotFoundError(
            "The sandbox folder does not exist. Run generate_canaries.py first."
        )

    files = [
        path
        for path in SANDBOX_DIRECTORY.rglob("*")
        if path.is_file() and not path.name.endswith(".locked")
    ]

    print(f"[STARTED] Mock ransomware PID: {os.getpid()}")
    print(f"[TARGET] {SANDBOX_DIRECTORY}")
    print(f"[FILES FOUND] {len(files)}\n")

    for file_path in files:
        file_path = safe_path(file_path)
        relative_path = file_path.relative_to(SANDBOX_DIRECTORY)

        print(f"[MODIFYING] {relative_path}")

        with file_path.open("ab") as file:
            file.write(os.urandom(256))
            file.flush()
            time.sleep(DELAY)

        locked_path = safe_path(
            file_path.with_name(file_path.name + ".locked")
        )

        file_path.rename(locked_path)
        print(f"[RENAMED] {relative_path} -> {relative_path}.locked\n")

        time.sleep(DELAY)

    print("[FINISHED] Mock ransomware simulation completed.")


if __name__ == "__main__":
    simulate_ransomware()