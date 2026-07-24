import hashlib
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MOCK_DIRECTORY = PROJECT_ROOT / "sandbox"
MANIFEST_PATH = PROJECT_ROOT / "manifest.json"


def sha256_file(file_path):
    file_hash = hashlib.sha256()

    with file_path.open("rb") as file:
        while chunk := file.read(65536):
            file_hash.update(chunk)

    return file_hash.hexdigest()


def create_baseline():
    if not MOCK_DIRECTORY.exists():
        raise FileNotFoundError(
            "The sandbox folder does not exist. Run generate_canaries.py first."
        )

    manifest = {}

    for file_path in sorted(MOCK_DIRECTORY.rglob("*")):
        if not file_path.is_file():
            continue

        resolved_path = file_path.resolve()
        file_info = resolved_path.stat()

        manifest[str(resolved_path)] = {
            "sha256": sha256_file(resolved_path),
            "mtime": file_info.st_mtime,
            "inode": file_info.st_ino,
        }

        print(f"[HASHED] {resolved_path.relative_to(MOCK_DIRECTORY)}")

    with MANIFEST_PATH.open("w", encoding="utf-8") as file:
        json.dump(manifest, file, indent=4)

    print(f"\nBaseline created for {len(manifest)} files.")
    print(f"Manifest saved at:\n{MANIFEST_PATH}")


if __name__ == "__main__":
    create_baseline()