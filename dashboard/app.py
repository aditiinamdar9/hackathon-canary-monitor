import json
from pathlib import Path
from flask import Flask, jsonify, render_template

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EVENTS_PATH = PROJECT_ROOT / "detection_engine" / "events.jsonl"

app = Flask(__name__)


def calculate_risk(event):
    action = event.get("action", "").lower()
    suspects = event.get("suspect_processes", [])

    if suspects and action in {"deleted", "moved"}:
        return 98

    if suspects:
        return 95

    if action in {"deleted", "moved"}:
        return 85

    if event.get("reason") == "hash mismatch":
        return 75

    return 60


def latest_event():
    if not EVENTS_PATH.exists():
        return None

    lines = EVENTS_PATH.read_text(encoding="utf-8").splitlines()

    for line in reversed(lines):
        try:
            event = json.loads(line)
            event["risk_score"] = calculate_risk(event)
            return event
        except json.JSONDecodeError:
            continue

    return None


@app.route("/")
def dashboard():
    return render_template("index.html")


@app.route("/api/latest-event")
def get_latest_event():
    event = latest_event()

    if event is None:
        return jsonify({
            "status": "protected",
            "event": None
        })

    return jsonify({
        "status": "threat",
        "event": event
    })


if __name__ == "__main__":
    app.run(debug=True)