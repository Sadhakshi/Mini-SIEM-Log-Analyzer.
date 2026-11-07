import argparse
import csv
import json
import html
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
    # Password spraying: one IP fails against multiple distinct usernames in a window.
    for ip, failures in sorted(failed_by_ip.items()):
        for end, current in enumerate(failures):
            recent = [e for e in failures[:end + 1]
                      if timedelta(0) <= current["parsed_timestamp"] - e["parsed_timestamp"] <= timedelta(minutes=window_minutes)]
            users = sorted({e["username"] for e in recent})
            if len(users) >= threshold:
                alerts.append({
                    "type": "POSSIBLE_PASSWORD_SPRAY", "severity": "HIGH", "entity": ip,
                    "count": len(recent), "distinct_users": len(users),
                    "first_seen": recent[0]["timestamp"], "last_seen": current["timestamp"],
                    "description": "Failures across multiple accounts from one source; investigate context",
                })
                break

    mapping = {
        "REPEATED_FAILURES_BY_IP": ("T1110", "Brute Force"),
        "REPEATED_FAILURES_BY_USER": ("T1110", "Brute Force"),
        "SUCCESS_AFTER_FAILURES": ("T1110", "Brute Force"),
        "POSSIBLE_PASSWORD_SPRAY": ("T1110.003", "Password Spraying"),
    }
    for alert in alerts:
        technique_id, technique_name = mapping[alert["type"]]
        alert["mitre_attack"] = {"technique_id": technique_id, "technique_name": technique_name}
        alert["investigation_note"] = "Review account context, source reputation and related events; this rule is not proof of compromise."
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


def render_dashboard(report, path):
    """Write a static, offline HTML report; no server or external libraries."""
    summary = report["summary"]
    cards = "".join(f'<div class="card"><small>{html.escape(k.replace("_", " ").title())}</small><strong>{html.escape(str(v))}</strong></div>'
                    for k, v in summary.items() if k != "alerts_by_severity")
    rows = "".join(
        "<tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in (
            a["severity"], a["type"], a["entity"], a["count"],
            a["first_seen"], a["mitre_attack"]["technique_id"])) + "</tr>"
        for a in report["alerts"]
    )
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Mini SIEM | SOC Dashboard</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{{font-family:system-ui;background:#0b1220;color:#e5eaf3;margin:0;padding:35px;}}
main{{max-width:1150px;margin:auto}}h1{{color:#8bd5ff}}.sub{{color:#9caac1}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:15px;margin:28px 0}}
.card{{background:#172238;border:1px solid #314158;border-radius:12px;padding:20px}}
small{{display:block;color:#9caac1;text-transform:capitalize}}strong{{font-size:29px;display:block;margin-top:8px}}
table{{width:100%;border-collapse:collapse;background:#172238}}th,td{{text-align:left;padding:13px;border-bottom:1px solid #314158}}
th{{color:#8bd5ff}}.scroll{{overflow-x:auto}}footer{{color:#9caac1;margin-top:25px}}</style></head>
<body><main><h1>🛡 Mini SIEM — SOC Dashboard</h1>
<p class="sub">Offline educational dashboard · Synthetic authentication data</p>
<div class="cards">{cards}</div><h2>Detection alerts</h2>
<div class="scroll"><table><thead><tr><th>Severity</th><th>Rule</th><th>Entity</th><th>Events</th><th>First seen</th><th>MITRE</th></tr></thead>
<tbody>{rows or '<tr><td colspan="6">No alerts</td></tr>'}</tbody></table></div>
<footer>MITRE ATT&CK mappings are indicative. Alerts require analyst investigation, not proof of malicious activity.</footer>
</main></body></html>"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(page, encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="Analyse synthetic authentication logs")
    parser.add_argument("--input", type=Path, default=Path("sample_data/sample_logs.csv"))
    parser.add_argument("--output", type=Path, default=Path("reports/incident_report.json"))
    parser.add_argument("--dashboard", type=Path, default=Path("reports/dashboard.html"))
    args = parser.parse_args()
    try:
        events = load_events(args.input)
        alerts = detect_alerts(events)
        report = build_report(events, alerts)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        render_dashboard(report, args.dashboard)
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
    print(f"Dashboard saved to: {args.dashboard}")
    print("Note: Alerts are indicators for investigation, not proof of an attack.")


if __name__ == "__main__":
    main()
