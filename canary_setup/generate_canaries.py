from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MOCK_DIRECTORY = PROJECT_ROOT / "sandbox"

CANARY_FILES = {
    "Finance/Q3_financials.xlsx": b"Quarter, Revenue, Expenses\nQ3, 125000, 84000\n",
    "HR/employee_records.csv": b"employee_id, name, department\n10321, Bob, Engineering\n",
    "passwords.txt": b"admin: admin123\nuser: userpass\n",
    "Projects/project_notes.docx": b"Our project notes for Q3.\n",
    "Personal_photo.jpg": b"FAKE IMAGE DATA FOR NOW...\n",
}


def safe_path(relative_path):
    destination = (MOCK_DIRECTORY / relative_path).resolve()
    mock_root = MOCK_DIRECTORY.resolve()

    if not destination.is_relative_to(mock_root):
        raise ValueError(f"Unsafe file path blocked: {relative_path}")

    return destination


def generate_canaries():
    MOCK_DIRECTORY.mkdir(parents=True, exist_ok=True)

    for relative_path, content in CANARY_FILES.items():
        destination = safe_path(relative_path)
        destination.parent.mkdir(parents=True, exist_ok=True)

        if destination.exists():
            print(f"[SKIPPED] Already exists: {relative_path}")
            continue

        destination.write_bytes(content)
        print(f"[CREATED] {relative_path}")

    print(f"\nCanary files are located at:\n{MOCK_DIRECTORY}")


if __name__ == "__main__":
    generate_canaries()