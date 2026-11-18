"""Unit tests for the standalone synthetic failed-login detector."""

import unittest

from log_analyzer import detect_failed_logins


def event(seconds, ip="192.0.2.10", status="failed"):
    return {"time": f"2026-10-01T10:{seconds // 60:02d}:{seconds % 60:02d}",
            "ip": ip, "status": status}


class FailedLoginDetectorTests(unittest.TestCase):
    def test_three_failures_within_one_minute_alert(self):
        alerts = detect_failed_logins([event(0), event(30), event(50)])
        self.assertEqual(alerts, [{"ip": "192.0.2.10", "count": 3, "window_seconds": 60}])

    def test_two_failures_do_not_alert(self):
        self.assertEqual(detect_failed_logins([event(0), event(30)]), [])

    def test_failures_outside_window_do_not_alert(self):
        self.assertEqual(detect_failed_logins([event(0), event(61), event(122)]), [])

    def test_separate_ip_addresses_are_not_combined(self):
        self.assertEqual(detect_failed_logins([
            event(0), event(20, "198.51.100.20"), event(40),
        ]), [])

    def test_successful_logins_do_not_count(self):
        self.assertEqual(detect_failed_logins([
            event(0), event(20, status="success"), event(40),
        ]), [])

    def test_unsorted_events_still_alert(self):
        self.assertEqual(len(detect_failed_logins([
            event(50), event(0), event(30),
        ])), 1)

    def test_exact_sixty_second_boundary_counts(self):
        self.assertEqual(len(detect_failed_logins([
            event(0), event(30), event(60),
        ])), 1)


if __name__ == "__main__":
    unittest.main()
