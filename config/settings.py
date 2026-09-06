#!/usr/bin/env python3
"""
config/settings.py

Every tunable value in PrecursorGuard, in one place. Previously these
were duplicated across detection/behavioral_detector.py and
agent/session_tracker.py (SECURITY_PROCESS_NAMES, WINDOW_SECONDS) and
scoring/risk_score.py (weights, threshold) — any change had to be
made in multiple files and it was easy to make them drift out of
sync. Now every module imports from here.

Log any change to these values in docs/DECISIONS.md — the paper's
methodology section needs to justify them.
"""

# --- Risk scoring ---
# NOTE (see docs/DECISIONS.md): driver_reputation was originally weighted at
# 0.4 and the burst path *required* a LOLDrivers hash match. That makes the
# whole system, in effect, a signature detector — a driver that isn't yet in
# the LOLDrivers list (a zero-day / unlisted BYOVD driver) could run the full
# priv-esc -> EDR-kill chain in seconds and still slip under ALERT_THRESHOLD,
# because privilege_escalation + process_kill alone only sum to 0.5. That's
# exactly backwards for a *precursor/behavioral* detector: hash reputation
# should raise confidence, not gate it. Weights rebalanced so behavior alone
# (privilege escalation + security-process kill, the two signals no
# ransomware precursor skips) can already cross ALERT_THRESHOLD on its own.
# Three primary signals weighted equally (0.30 each) plus a smaller
# precursor-command signal (0.10). This makes the rule explainable in one
# sentence for the viva: "any two of {known-bad driver, privilege
# escalation, security-process kill} crossing together is enough to
# alert" (0.30 + 0.30 = 0.60 = ALERT_THRESHOLD), with the precursor-command
# count nudging borderline single-signal cases over the line.
RISK_WEIGHTS = {
    "driver_reputation": 0.30,
    "privilege_escalation": 0.30,
    "process_kill": 0.30,
    "precursor_command": 0.10,
}
ALERT_THRESHOLD = 0.6
PRECURSOR_COUNT_CAP = 3  # precursor_command sub-score reaches 1.0 once this many commands are seen

# --- Behavioral correlation ---
WINDOW_SECONDS = 60  # driver-load -> security-process-kill correlation window (batch AND live agent)

BURST_WINDOW_SECONDS = 5  # driver-load -> security-process-kill correlation window for burst detection

SECURITY_PROCESS_NAMES = {"msmpeng.exe", "fake_edr.exe", "sentinelagent.exe"}

# --- Live agent ---
DEFAULT_POLL_INTERVAL_SECONDS = 2  # Windows live source polling interval
LIVE_ALERTS_LOG_PATH = "reports/live_alerts.csv"

# --- Reference data ---
LOLDRIVERS_REFERENCE_PATH = "data/loldrivers_reference.csv"
