"""Standard-library unit tests for the independent SOC demonstration."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from log_analyzer import AuthEvent, detect_failed_logins, parse_timestamp, read_events

PROJECT_DIR = Path(__file__).resolve().parent
BASE = datetime(2026, 10, 1, 10, 0, 0, tzinfo=timezone.utc)


def sample(seconds: int, ip: str = "192.0.2.10", status: str = "failed") -> AuthEvent:
    return AuthEvent(BASE + timedelta(seconds=seconds), ip, "lab-user", status)


class FailedLoginTests(unittest.TestCase):
    def test_three_failures_alert(self):
        alerts = detect_failed_logins([sample(0), sample(25), sample(50)])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].source_ip, "192.0.2.10")
        self.assertEqual(alerts[0].count, 3)

    def test_two_failures_do_not_alert(self):
        self.assertEqual(detect_failed_logins([sample(0), sample(20)]), [])

    def test_events_outside_window_do_not_alert(self):
        self.assertEqual(detect_failed_logins([sample(0), sample(61), sample(122)]), [])

    def test_separate_ips_not_combined(self):
        self.assertEqual(detect_failed_logins([
            sample(0), sample(20, "198.51.100.20"), sample(40)
        ]), [])

    def test_success_ignored(self):
        self.assertEqual(detect_failed_logins([
            sample(0), sample(20, status="success"), sample(40)
        ]), [])

    def test_unsorted_events_still_alert(self):
        self.assertEqual(len(detect_failed_logins([
            sample(50), sample(0), sample(25)
        ])), 1)

    def test_exact_window_boundary_inclusive(self):
        self.assertEqual(len(detect_failed_logins([
            sample(0), sample(30), sample(60)
        ])), 1)

    def test_multiple_sources_generate_independent_alerts(self):
        alerts = detect_failed_logins([
            sample(0), sample(10), sample(30),
            sample(90, "198.51.100.20"),
            sample(100, "198.51.100.20"),
            sample(110, "198.51.100.20"),
        ])
        self.assertEqual({a.source_ip for a in alerts}, {"192.0.2.10", "198.51.100.20"})

    def test_empty_input(self):
        self.assertEqual(detect_failed_logins([]), [])

    def test_invalid_threshold(self):
        with self.assertRaises(ValueError):
            detect_failed_logins([sample(0)], threshold=0)

    def test_invalid_window(self):
        with self.assertRaises(ValueError):
            detect_failed_logins([sample(0)], window_seconds=-1)

    def test_timestamp_with_offset_is_normalized(self):
        self.assertEqual(parse_timestamp("2026-10-01T12:00:00+02:00"), BASE)

    def test_naive_timestamp_rejected(self):
        with self.assertRaises(ValueError):
            parse_timestamp("2026-10-01T10:00:00")

    def test_missing_csv_header_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "invalid.csv"
            csv_path.write_text("timestamp,source_ip,status\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "missing columns"):
                read_events(csv_path)

    def test_invalid_csv_ip_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "invalid.csv"
            csv_path.write_text(
                "timestamp,source_ip,username,status\n"
                "2026-10-01T10:00:00Z,not-an-ip,alice,failed\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "CSV line 2"):
                read_events(csv_path)

    def test_csv_sample_contains_one_detectable_source(self):
        alerts = detect_failed_logins(read_events(PROJECT_DIR / "data/synthetic_auth_events.csv"))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].source_ip, "192.0.2.10")

    def test_cli_example_output(self):
        result = subprocess.run(
            [sys.executable, str(PROJECT_DIR / "log_analyzer.py")],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("[ALERT] 192.0.2.10: 3 failed logins", result.stdout)
        self.assertIn("Analysis complete: 1 source(s) flagged.", result.stdout)


if __name__ == "__main__":
    unittest.main()
