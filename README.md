# SIEM Log Aggregation & Query Engine

A Python-based SIEM tool that ingests Windows Event Logs, supports 
SPL-inspired query language for threat hunting, and auto-exports 
results to JSON for further analysis.

---

## Demo Results

Running against 100 generated Windows Event Log entries:

```
siem> stats count by severity
severity  count
    high    161
     low    158
critical     94
  medium     87

siem> filter severity=critical
→ Returns all Audit Log Cleared (EventID 1102) events

siem> where event_id=4625
→ Returns all failed logon attempts
```

---

## Features

- SPL-inspired query language (search, where, filter, stats, sort, head)
- Ingests Windows Event Log data in JSON format
- Auto-saves every query result to output/ with timestamp
- Detects high-severity events including audit log clearing and scheduled task creation
- Covers EventIDs: 4625, 4624, 4688, 4698, 4720, 1102

---

## Query Language Reference

| Command | Example | Description |
|---|---|---|
| search | search powershell | Free text search across all fields |
| where | where event_id=4625 | Filter by exact field value |
| filter | filter severity=critical | Filter by severity level |
| stats count by | stats count by user | Count events grouped by field |
| sort | sort timestamp | Sort results descending |
| head | head 20 | Show first N results |

---

## MITRE ATT&CK Coverage

| Event ID | Description | MITRE Technique |
|---|---|---|
| 4625 | Failed logon attempt | T1110 Brute Force |
| 4698 | Scheduled task created | T1053.005 Scheduled Task |
| 4720 | User account created | T1136 Create Account |
| 1102 | Audit log cleared | T1070.001 Clear Windows Event Logs |
| 4688 | Process created | T1059 Command and Scripting Interpreter |

---

## Quick Start

```bash
pip install pandas flask colorama

python generate_logs.py     # Generate 500 sample log entries
python query_engine.py      # Launch interactive query engine
```

---

## Project Structure

```
siem-query/
├── logs/
│   └── windows_events.json     # Generated log data
├── output/
│   └── (query results saved here automatically)
├── generate_logs.py            # Log generator
├── query_engine.py             # Interactive SIEM query engine
└── README.md
```

---

## Author

Muneeba Sajjad — MSc Cyber Security, University of Hertfordshire

