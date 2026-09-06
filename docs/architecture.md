# PrecursorGuard — Architecture

## Folder structure

```
precursorguard/
├── agent/        live streaming detection (event_source.py, session_tracker.py, live_watcher.py)
├── scripts/      offline ingestion: evtx_to_csv.py, build_loldrivers_reference.py
├── data/         raw/, processed/, loldrivers_reference.csv
├── detection/    rule_detector.py, behavioral_detector.py, precursor_detector.py, pipeline.py
├── scoring/      risk_score.py — the weighted formula, isolated from detection logic
├── ml/           features.py, train_model.py
├── response/     alerts.py (fires + logs alerts), notifications.py (stub, not wired)
├── reports/      generate_report.py — PDF forensic report
├── dashboard/    app.py — Streamlit, mitre_mapping.json
├── config/       settings.py — every tunable constant, one place
├── tests/        pytest unit tests for scoring, detection, and the live agent
├── docs/         architecture.md (this file), DECISIONS.md
└── paper/        IEEE LaTeX source (Overleaf-synced)
```

Note on `response/`: this deliberately contains alerting and (a stub
for) notifications, and nothing else. There is no auto-remediation /
process-kill module. PrecursorGuard's stated scope is detect and
recommend, not auto-remediate (see the project guide, Part 1.3) — a
detector with kill authority on the endpoint is also a bigger target
for an attacker to abuse. If that scope changes, it's a real decision:
log it in docs/DECISIONS.md and get sign-off first, don't just add
the code.

## Data flow — batch (offline) path

```
Windows VM (isolated, host-only network)
   └─ Sysmon (SwiftOnSecurity config)
        └─ Windows Event Log (EVTX)
             └─ scripts/evtx_to_csv.py            → data/raw/*.csv (fixed schema)
                  └─ detection/simulate_harness.py  (synthetic data for safe dev/testing)
                       └─ data/processed/labeled_sessions.csv

data/processed/labeled_sessions.csv
   └─ detection/rule_detector.py         → LOLDrivers hash match
   └─ detection/behavioral_detector.py   → privilege escalation + security-process-kill sequence
   └─ detection/precursor_detector.py    → pre-encryption command patterns
        └─ scoring/risk_score.py         → weighted 0–1 RiskScore + alert flag
             └─ detection/pipeline.py    → reports/alerts.csv  (hybrid | rule_only | ml_only)

ml/features.py + ml/train_model.py
   └─ trains Random Forest / Logistic Regression / Gradient Boosting
        on the same signal table → ml/models/model.joblib + metrics.json

reports/alerts.csv + data/processed/labeled_sessions.csv
   └─ dashboard/app.py (Streamlit)
        → alert list, per-session timeline, MITRE ATT&CK tags
        → "Download Report" → response/report_generator.py → PDF
```

## Data flow — live (streaming) path

```
Windows endpoint, Sysmon running
   └─ agent/event_source.py (WindowsLiveEventSource, polls the live channel)
        └─ agent/session_tracker.py (rolling 60s window, rescored on every event)
             └─ scoring/risk_score.py (same formula as the batch path)
                  └─ response/alerts.py → reports/live_alerts.csv + console
                       └─ response/notifications.py (stub — not implemented yet)
```

Both paths call the exact same `scoring/risk_score.py` and read the
same `config/settings.py` — the live agent isn't a separate detection
logic, it's the same engine fed one event at a time instead of a
finished batch.

## Fixed CSV schema (do not change without updating every downstream script)

```
timestamp, event_id, process_name, process_guid, parent_process,
image_loaded, driver_signed, signer_name, target_process,
command_line, hashes, integrity_level
```

The synthetic harness and evaluation dataset add two more columns:
`session_id` (groups rows into one attack/benign sequence) and
`label` (ground truth — `attack` or `benign` — used only for evaluation,
never fed into the rule/behavioral detectors themselves). The live
agent doesn't use `session_id` at all — it infers a rolling window
from timestamps instead, since a real endpoint's events don't arrive
pre-grouped into sessions.

## Why sessions, not raw rows (batch path)

Every batch detector in this project reasons about a *sequence* of
events within one session (driver load → privilege escalation →
process kill → precursor command), not single rows in isolation.
`session_id` is how the batch pipeline groups raw Sysmon rows back
into that sequence, both for the synthetic harness and for a real VM
capture. The live agent achieves the same grouping with a sliding
time window instead of a session_id, since it has to work without the
benefit of already knowing where a session starts and ends.

