import random
import json
from datetime import datetime, timezone, timedelta

USERS = ["j.morris", "a.singh", "svc_backup", "admin", "guest"]
HOSTS = ["WKS-FIN-014", "SRV-DB-02", "WKS-HR-007", "DC-01"]
IPS = ["10.20.5.41", "45.155.205.92", "185.220.101.47", "10.20.1.15"]
EVENTS = [
    {"id": 4625, "desc": "Failed logon attempt", "severity": "medium"},
    {"id": 4624, "desc": "Successful logon", "severity": "low"},
    {"id": 4688, "desc": "Process created", "severity": "low"},
    {"id": 4698, "desc": "Scheduled task created", "severity": "high"},
    {"id": 4720, "desc": "User account created", "severity": "high"},
    {"id": 1102, "desc": "Audit log cleared", "severity": "critical"},
]

logs = []
base_time = datetime.now(timezone.utc) - timedelta(hours=24)

for i in range(500):
    event = random.choice(EVENTS)
    log = {
        "timestamp": (base_time + timedelta(minutes=i*3)).isoformat(),
        "event_id": event["id"],
        "description": event["desc"],
        "severity": event["severity"],
        "user": random.choice(USERS),
        "host": random.choice(HOSTS),
        "src_ip": random.choice(IPS),
        "process": random.choice(["powershell.exe", "cmd.exe",
                                   "svchost.exe", "explorer.exe"])
    }
    logs.append(log)

with open("logs/windows_events.json", "w") as f:
    json.dump(logs, f, indent=2)

print(f"Generated {len(logs)} log entries")
