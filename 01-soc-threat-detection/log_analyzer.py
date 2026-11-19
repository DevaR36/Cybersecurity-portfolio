"""Educational security event correlation using fictional authentication data.

Detects repeated failed sign-ins per source IP in an inclusive sliding time
window. It does not connect to a SIEM or use internship assessment data.

Examples:
    python log_analyzer.py
    python log_analyzer.py --input data/synthetic_auth_events.csv
    python log_analyzer.py --threshold 4 --window-seconds 120
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

DATA_PATH = Path(__file__).resolve().parent / "data" / "synthetic_auth_events.csv"
REQUIRED_COLUMNS = {"timestamp", "source_ip", "username", "status"}


@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    source_ip: str
    username: str
    status: str


@dataclass(frozen=True)
class Alert:
    source_ip: str
    count: int
    first_seen: datetime
    last_seen: datetime


def parse_timestamp(raw: str) -> datetime:
    """Return a UTC-aware timestamp; reject ambiguous local times."""
    try:
        parsed = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"Invalid ISO 8601 timestamp: {raw!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"Timestamp needs timezone information: {raw!r}")
    return parsed.astimezone(timezone.utc)


def read_events(csv_path: Path) -> list[AuthEvent]:
    """Read synthetic CSV, rejecting malformed rows with clear errors."""
    events: list[AuthEvent] = []
    with Path(csv_path).open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        missing = REQUIRED_COLUMNS - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"CSV missing columns: {', '.join(sorted(missing))}")
        for line_number, row in enumerate(reader, start=2):
            try:
                source_ip = (row["source_ip"] or "").strip()
                ipaddress.ip_address(source_ip)
                status = (row["status"] or "").strip().lower()
                if status not in {"failed", "success"}:
                    raise ValueError(f"Invalid status {status!r}")
                username = (row["username"] or "").strip()
                if not username:
                    raise ValueError("Missing username")
                events.append(
                    AuthEvent(
                        timestamp=parse_timestamp(row["timestamp"] or ""),
                        source_ip=source_ip,
                        username=username,
                        status=status,
                    )
                )
            except (ValueError, KeyError, TypeError) as exc:
                raise ValueError(f"CSV line {line_number}: {exc}") from exc
    return events


def detect_failed_logins(
    events: list[AuthEvent], *, threshold: int = 3, window_seconds: int = 60
) -> list[Alert]:
    """Return the first qualifying failed-login burst for each source IP.

    Boundaries are inclusive: 00:00, 00:30, 01:00 count as three events
    within sixty seconds. Usernames are deliberately not used for grouping.
    """
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    if window_seconds < 0:
        raise ValueError("window_seconds must be nonnegative")

    grouped: dict[str, list[datetime]] = defaultdict(list)
    for event in events:
        if event.status == "failed":
            if event.timestamp.tzinfo is None or event.timestamp.utcoffset() is None:
                raise ValueError("Event timestamps must include timezone information")
            grouped[event.source_ip].append(event.timestamp.astimezone(timezone.utc))

    alerts: list[Alert] = []
    for source_ip, times in grouped.items():
        window: deque[datetime] = deque()
        for timestamp in sorted(times):
            window.append(timestamp)
            while (timestamp - window[0]).total_seconds() > window_seconds:
                window.popleft()
            if len(window) >= threshold:
                alerts.append(
                    Alert(
                        source_ip=source_ip,
                        count=len(window),
                        first_seen=window[0],
                        last_seen=timestamp,
                    )
                )
                break  # One demonstration alert per source, avoiding repeated noise.
    return sorted(alerts, key=lambda a: (a.last_seen, a.source_ip))


def main() -> int:
    parser = argparse.ArgumentParser(description="Synthetic failed-login burst detector")
    parser.add_argument("--input", type=Path, default=DATA_PATH, help="CSV input path")
    parser.add_argument("--threshold", type=int, default=3, help="Minimum failed logins")
    parser.add_argument("--window-seconds", type=int, default=60, help="Inclusive window length")
    args = parser.parse_args()

    try:
        events = read_events(args.input)
        alerts = detect_failed_logins(
            events, threshold=args.threshold, window_seconds=args.window_seconds
        )
    except (ValueError, OSError) as exc:
        parser.error(str(exc))

    for alert in alerts:
        print(
            f"[ALERT] {alert.source_ip}: {alert.count} failed logins "
            f"between {alert.first_seen:%Y-%m-%dT%H:%M:%SZ} "
            f"and {alert.last_seen:%Y-%m-%dT%H:%M:%SZ}"
        )
    print(f"Analysis complete: {len(alerts)} source(s) flagged.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
