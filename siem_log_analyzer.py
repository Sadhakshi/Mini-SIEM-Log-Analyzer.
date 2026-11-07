import argparse
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

REQUIRED_FIELDS = {"timestamp", "username", "source_ip", "event_type", "status"}
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"


def load_events(path):
    with path.open(newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        if not reader.fieldnames or not REQUIRED_FIELDS.issubset(reader.fieldnames):
            raise ValueError(f"CSV must contain: {', '.join(sorted(REQUIRED_FIELDS))}")
        events = []
        for row_number, row in enumerate(reader, start=2):
            try:
                timestamp = datetime.strptime(row["timestamp"], TIME_FORMAT)
                if not all(row.get(field) for field in REQUIRED_FIELDS):
                    raise ValueError("missing required value")
            except (ValueError, TypeError) as error:
                raise ValueError(f"Invalid row {row_number}: {error}") from error
            events.append({**row, "parsed_timestamp": timestamp})
    return sorted(events, key=lambda event: event["parsed_timestamp"])


def detect_alerts(events, threshold=4, window_minutes=10):
    alerts = []
    failed_by_ip = defaultdict(list)
    failed_by_user = defaultdict(list)
    for event in events:
        if event["event_type"] == "LOGIN" and event["status"] == "FAILED":
            failed_by_ip[event["source_ip"]].append(event)
            failed_by_user[event["username"]].append(event)

    def detect_bursts(groups, label, severity):
        for key, failures in sorted(groups.items()):
            start = 0
            for end, current in enumerate(failures):
                while current["parsed_timestamp"] - failures[start]["parsed_timestamp"] > timedelta(minutes=window_minutes):
                    start += 1
                if end - start + 1 >= threshold:
                    alerts.append({
                        "type": label,
                        "severity": severity,
                        "entity": key,
                        "count": end - start + 1,
                        "first_seen": failures[start]["timestamp"],
                        "last_seen": current["timestamp"],
                        "description": f"At least {threshold} failed logins within {window_minutes} minutes",
                    })
                    break  # One summary alert per entity for this demo

    detect_bursts(failed_by_ip, "REPEATED_FAILURES_BY_IP", "HIGH")
    detect_bursts(failed_by_user, "REPEATED_FAILURES_BY_USER", "MEDIUM")

    # A successful login shortly after multiple failures from the same IP.
    for ip, failures in sorted(failed_by_ip.items()):
        successes = [e for e in events if e["source_ip"] == ip and e["event_type"] == "LOGIN" and e["status"] == "SUCCESS"]
        for success in successes:
            recent = [e for e in failures if timedelta(0) <= success["parsed_timestamp"] - e["parsed_timestamp"] <= timedelta(minutes=window_minutes)]
            if len(recent) >= threshold:
                alerts.append({
                    "type": "SUCCESS_AFTER_FAILURES",
                    "severity": "HIGH",
                    "entity": ip,
                    "count": len(recent),
                    "first_seen": recent[0]["timestamp"],
                    "last_seen": success["timestamp"],
                    "description": "Successful login after multiple failed attempts from the same IP; investigate context",
                })
                break
    return alerts


def build_report(events, alerts):
    return {
        "project": "Mini SIEM Log Analyzer",
        "data_type": "Synthetic demonstration logs",
        "summary": {
            "total_events": len(events),
            "failed_logins": sum(e["event_type"] == "LOGIN" and e["status"] == "FAILED" for e in events),
            "successful_logins": sum(e["event_type"] == "LOGIN" and e["status"] == "SUCCESS" for e in events),
            "alerts_generated": len(alerts),
            "alerts_by_severity": dict(sorted(Counter(a["severity"] for a in alerts).items())),
        },
        "alerts": alerts,
    }


def main():
    parser = argparse.ArgumentParser(description="Analyse synthetic authentication logs")
    parser.add_argument("--input", type=Path, default=Path("sample_data/sample_logs.csv"))
    parser.add_argument("--output", type=Path, default=Path("reports/incident_report.json"))
    args = parser.parse_args()
    try:
        events = load_events(args.input)
        alerts = detect_alerts(events)
        report = build_report(events, alerts)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError) as error:
        parser.exit(1, f"Error: {error}\n")

    print("=" * 56)
    print("               MINI SIEM LOG ANALYZER")
    print("=" * 56)
    for key, value in report["summary"].items():
        print(f"{key.replace('_', ' ').title():25}: {value}")
    print("\nSECURITY ALERTS")
    print("-" * 56)
    for alert in alerts:
        print(f"[{alert['severity']}] {alert['type']} | {alert['entity']} | {alert['count']} failures")
    if not alerts:
        print("No threshold-based alerts detected.")
    print(f"\nReport saved to: {args.output}")
    print("Note: Alerts are indicators for investigation, not proof of an attack.")


if __name__ == "__main__":
    main()
