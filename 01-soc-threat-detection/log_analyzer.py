"""Educational failed-login detector using only fictional authentication events.

This is an independent demonstration, not an internship task solution or a
production security detection. All IP addresses are reserved for documentation.
"""

from collections import defaultdict, deque
from datetime import datetime


SYNTHETIC_EVENTS = [
    {"time": "2026-10-01T10:00:00", "ip": "192.0.2.10", "status": "failed"},
    {"time": "2026-10-01T10:00:30", "ip": "192.0.2.10", "status": "failed"},
    {"time": "2026-10-01T10:00:50", "ip": "192.0.2.10", "status": "failed"},
    {"time": "2026-10-01T10:02:00", "ip": "198.51.100.20", "status": "failed"},
    {"time": "2026-10-01T10:04:00", "ip": "198.51.100.20", "status": "failed"},
]


def detect_failed_logins(events, threshold=3, window_seconds=60):
    """Return one alert per IP with >= threshold failures within the window.

    Events must contain ISO-8601 timestamps, an IP, and a status. The demo
    uses timestamps in one consistent time zone (UTC or naive, not mixed).
    """
    if threshold < 1 or window_seconds < 0:
        raise ValueError("threshold must be >= 1 and window_seconds must be >= 0")

    grouped = defaultdict(list)
    for event in events:
        if event.get("status") == "failed":
            grouped[event["ip"]].append(datetime.fromisoformat(event["time"]))

    alerts = []
    for ip, timestamps in sorted(grouped.items()):
        window = deque()
        for timestamp in sorted(timestamps):
            window.append(timestamp)
            while (timestamp - window[0]).total_seconds() > window_seconds:
                window.popleft()
            if len(window) >= threshold:
                alerts.append({
                    "ip": ip,
                    "count": len(window),
                    "window_seconds": window_seconds,
                })
                break
    return alerts


if __name__ == "__main__":
    for alert in detect_failed_logins(SYNTHETIC_EVENTS):
        print(
            f"[ALERT] Suspicious login activity from {alert['ip']}: "
            f"{alert['count']} failures within {alert['window_seconds']} seconds"
        )
    print("Analysis complete.")
