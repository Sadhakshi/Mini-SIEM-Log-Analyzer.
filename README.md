# Mini SIEM Log Analyzer

A beginner-friendly Python security monitoring project that reads **synthetic authentication events** from CSV, detects suspicious login patterns, and exports a JSON incident summary. Built with Python's standard library only.

## Features

- Parse and validate timestamped CSV security events.
- Detect four or more failed logins within ten minutes, grouped by source IP or username.
- Flag a successful login following multiple failures from the same IP.
- Print severity-labelled alerts and event statistics.
- Export findings to `reports/incident_report.json`.

## Quick start

Requires Python 3.9+.

```bash
python3 siem_log_analyzer.py
```

Or specify input/output paths:

```bash
python3 siem_log_analyzer.py --input sample_data/sample_logs.csv --output reports/incident_report.json
```

## Project layout

```text
Mini-SIEM-Log-Analyzer/
├── siem_log_analyzer.py
├── sample_data/
│   └── sample_logs.csv
├── reports/
│   └── incident_report.json (generated)
├── README.md
└── .gitignore
```

## Detection logic

| Rule | Trigger | Severity |
| --- | --- | --- |
| Repeated failures by IP | >=4 failed logins from an IP within 10 minutes | HIGH |
| Repeated failures by username | >=4 failed logins for a username within 10 minutes | MEDIUM |
| Success after failures | Successful login from an IP following >=4 failures within 10 minutes | HIGH |

The rules generate one summary alert per matching entity. Multiple alerts may describe the same sequence. They are **investigation indicators**, not proof of an attack. This is a teaching demo, not a production SIEM: it has no real-time ingestion, persistence, tuning, or enrichment.

## Sample data and privacy

All names and events are fictional. IP addresses use documentation-only ranges (RFC 5737). Do not publish real credentials, personal information, or confidential logs.

## Next improvements

- Unit tests for edge cases and time-window boundaries.
- Alert deduplication and false-positive analysis.
- Stream processing and richer detection rules.
- Dashboard and analyst triage workflow.
