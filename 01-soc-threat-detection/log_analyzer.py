
from collections import defaultdict, deque
from datetime import datetime

# Synthetic authentication events for demonstration
events = [
    {"time": "2026-10-01T10:00:00", "ip": "192.0.2.10", "status": "failed"},
    {"time": "2026-10-01T10:00:30", "ip": "192.0.2.10", "status": "failed"},
    {"time": "2026-10-01T10:00:50", "ip": "192.0.2.10", "status": "failed"},
    {"time": "2026-10-01T10:02:00", "ip": "198.51.100.20", "status": "failed"},
    {"time": "2026-10-01T10:04:00", "ip": "198.51.100.20", "status": "failed"},
]

THRESHOLD = 3
WINDOW_SECONDS = 60

# Group authentication events by source IP
grouped = defaultdict(list)

for event in events:
    if event["status"] == "failed":
        grouped[event["ip"]].append(
            datetime.fromisoformat(event["time"])
        )

# Detect repeated failures within a sliding time window
for ip, timestamps in grouped.items():
    window = deque()

    for timestamp in sorted(timestamps):
        window.append(timestamp)

        while (timestamp - window[0]).total_seconds() > WINDOW_SECONDS:
            window.popleft()

        if len(window) >= THRESHOLD:
            print(
                f"[ALERT] Suspicious login activity from {ip}: "
                f"{len(window)} failures within 60 seconds"
            )
            break

print("Analysis complete.")
