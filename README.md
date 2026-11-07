# Mini SIEM Log Analyzer — Intermediate Portfolio Edition

Python-based **educational SOC log analysis project** that reads synthetic CSV authentication events, correlates failures over time, creates severity-labelled findings, maps indicative MITRE ATT&CK techniques, and exports a JSON report and offline HTML dashboard. **Not a production SIEM.**

## Quick start (Python 3.9+, no third-party packages)

```bash
python3 siem_log_analyzer.py
python3 -m unittest discover -s tests -v
```

Open `reports/dashboard.html` in your browser after running the script. Reports are generated from the synthetic CSV.

## Features

- Validate and chronologically sort timestamped CSV login/logout records.
- Detect 4+ failures per IP or username within a 10-minute sliding window.
- Detect successful authentication after multiple failures from the same IP.
- Detect **possible password spraying** when one IP fails against 4+ distinct users in 10 minutes.
- Annotate findings with MITRE ATT&CK **T1110 (Brute Force)** or **T1110.003 (Password Spraying)** as investigative hypotheses, not confirmed techniques.
- Generate `reports/incident_report.json` and a responsive offline `reports/dashboard.html`.
- Run six automated tests with `unittest`.

## Project structure

```text
siem_log_analyzer.py         # ingestion, detection, reports, dashboard
sample_data/sample_logs.csv # synthetic demonstration events
reports/incident_report.json # generated report
reports/dashboard.html       # generated dashboard
 tests/test_siem.py          # unit tests
README.md
.gitignore
```

## Sample alert investigation workflow

1. Review severity, rule name, time window, source IP and affected users.
2. Inspect related authentication events and check whether an authorised test explains the activity.
3. Consider legitimate causes such as mistyped passwords or shared NAT addresses.
4. Escalate suspicious findings for investigation; **do not assume an alert proves an attack**.

## Detection design and limitations

Rules operate on a small, local CSV. They produce one summary alert per matching entity, so separate rules may flag overlapping events. Severity is a demonstration label, not a risk score. There is no streaming ingestion, threat intelligence, user baselining, role-based access control, alert lifecycle, persistence or false-positive tuning. MITRE mappings are analyst aids, not proof of attacker behaviour. All IPs use documentation-only address ranges and all users are fictional.

## How to discuss this project in an interview

Explain the CSV ingestion and validation, time-window correlation, threshold choice, MITRE mappings, evidence in JSON, HTML report generation and unit tests. Describe a false positive (multiple legitimate users behind one IP) and a next improvement (event-level correlation or a real event format adapter).

## GitHub upload

Upload the extracted files and folders to your existing repository. Replace older files with matching names, and commit with message `Upgrade Mini SIEM with correlation, MITRE mapping, dashboard and tests`.
