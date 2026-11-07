import unittest
from datetime import datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from siem_log_analyzer import load_events, detect_alerts, build_report, render_dashboard

DATA = Path(__file__).resolve().parents[1] / "sample_data/sample_logs.csv"

class SIEMTests(unittest.TestCase):
    def setUp(self):
        self.events = load_events(DATA)

    def test_csv_loaded_and_sorted(self):
        self.assertEqual(len(self.events), 13)
        self.assertEqual(self.events, sorted(self.events, key=lambda x: x["parsed_timestamp"]))

    def test_password_spray_detected(self):
        alerts = detect_alerts(self.events)
        self.assertTrue(any(a["type"] == "POSSIBLE_PASSWORD_SPRAY" and a["entity"] == "203.0.113.40" for a in alerts))

    def test_success_after_failures(self):
        self.assertTrue(any(a["type"] == "SUCCESS_AFTER_FAILURES" for a in detect_alerts(self.events)))

    def test_no_alert_for_single_failure(self):
        self.assertEqual(detect_alerts(self.events[:2]), [])

    def test_mitre_mapping(self):
        for alert in detect_alerts(self.events):
            self.assertTrue(alert["mitre_attack"]["technique_id"].startswith("T"))

    def test_dashboard_generated(self):
        report = build_report(self.events, detect_alerts(self.events))
        with TemporaryDirectory() as directory:
            output = Path(directory) / "dashboard.html"
            render_dashboard(report, output)
            self.assertIn("SOC Dashboard", output.read_text())

if __name__ == "__main__":
    unittest.main()
