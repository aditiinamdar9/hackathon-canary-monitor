import json
from pathlib import Path
from flask import Flask, jsonify, render_template

PROJECT_ROOT = Path(__file__).resolve().parents[1]

EVENTS_PATH = (
    PROJECT_ROOT
    / "detection_engine"
    / "events.jsonl"
)

INCIDENTS_PATH = (
    PROJECT_ROOT
    / "alerting"
    / "incidents.log"
)

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

    try:
        lines = EVENTS_PATH.read_text(
            encoding="utf-8"
        ).splitlines()
    except OSError:
        return None

    for line in reversed(lines):
        try:
            event = json.loads(line)

            if "risk_score" not in event:
                event["risk_score"] = calculate_risk(event)

            return event

        except json.JSONDecodeError:
            continue

    return None


def latest_response(event):
    if event is None or not INCIDENTS_PATH.exists():
        return None

    try:
        lines = INCIDENTS_PATH.read_text(
            encoding="utf-8"
        ).splitlines()
    except OSError:
        return None

    for line in reversed(lines):
        try:
            incident = json.loads(line)
        except json.JSONDecodeError:
            continue

        correlated_event = incident.get(
            "correlated_event",
            {}
        )

        same_path = (
            correlated_event.get("path")
            == event.get("path")
        )

        same_time = (
            correlated_event.get("detected_at")
            == event.get("timestamp")
        )

        if same_path and same_time:
            return incident.get("response")

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
            "event": None,
            "response": None
        })

    response = latest_response(event)

    return jsonify({
        "status": "threat",
        "event": event,
        "response": response
    })


if __name__ == "__main__":
    app.run(debug=True)