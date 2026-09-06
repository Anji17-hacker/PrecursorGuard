#!/usr/bin/env python3
"""
behavioral_detector.py

Phase 6 of the roadmap. An unrecognized driver is not inherently
malicious, so this module does NOT rely on the hash match alone. It
looks, per session, for the actual behavioral sequence:

    driver load -> (short window) -> privilege escalation indicator
                -> (short window) -> security-process termination

SECURITY_PROCESS_NAMES is deliberately small and explicit — extend it
in config/settings.py to match whatever your simulation harness / real
EDR product uses.
"""
import os
import sys
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import SECURITY_PROCESS_NAMES, WINDOW_SECONDS


def _basename(path):
    if not isinstance(path, str) or not path:
        return ""
    return path.replace("\\", "/").split("/")[-1].lower()


def score_session(session_df):
    """
    Returns a dict of behavioral signals for one session's rows, including
    event timestamps needed by the batch burst detector and evaluation:
        privilege_escalation_flag (0/1)
        security_process_killed (0/1)
        driver_load_present (0/1)
        time_since_driver_load (seconds, or -1 if no driver load)
        driver_load_time
        privilege_escalation_time
        security_process_kill_time
        burst_seconds
    """
    session_df = session_df.sort_values("timestamp")
    session_df["timestamp"] = pd.to_datetime(session_df["timestamp"])

    driver_loads = session_df[session_df["event_id"] == 6]
    if driver_loads.empty:
        return {
            "privilege_escalation_flag": 0,
            "security_process_killed": 0,
            "driver_load_present": 0,
            "time_since_driver_load": -1,
            "driver_load_time": "",
            "privilege_escalation_time": "",
            "security_process_kill_time": "",
            "burst_seconds": None,
        }

    driver_load_time = driver_loads.iloc[0]["timestamp"]
    window_end = driver_load_time + pd.Timedelta(seconds=WINDOW_SECONDS)
    window_df = session_df[(session_df["timestamp"] >= driver_load_time) & (session_df["timestamp"] <= window_end)]

    # Privilege escalation: Event ID 1 rows with IntegrityLevel == System in the window
    priv_esc = window_df[(window_df["event_id"] == 1) & (window_df["integrity_level"].astype(str).str.lower() == "system")]
    privilege_escalation_flag = 1 if not priv_esc.empty else 0
    first_priv_time = priv_esc.iloc[0]["timestamp"] if privilege_escalation_flag else None

    # Security process kill: Event ID 5 rows whose process_name matches our watchlist
    kills = window_df[(window_df["event_id"] == 5) & (window_df["process_name"].apply(_basename).isin(SECURITY_PROCESS_NAMES))]
    security_process_killed = 1 if not kills.empty else 0
    first_kill_time = kills.iloc[0]["timestamp"] if security_process_killed else None

    time_since = 0
    if security_process_killed:
        time_since = (first_kill_time - driver_load_time).total_seconds()

    burst_seconds = None
    if first_priv_time is not None and first_kill_time is not None:
        burst_seconds = (max(first_priv_time, first_kill_time) - driver_load_time).total_seconds()

    return {
        "privilege_escalation_flag": privilege_escalation_flag,
        "security_process_killed": security_process_killed,
        "driver_load_present": 1,
        "time_since_driver_load": time_since,
        "driver_load_time": driver_load_time.isoformat(),
        "privilege_escalation_time": first_priv_time.isoformat() if first_priv_time is not None else "",
        "security_process_kill_time": first_kill_time.isoformat() if first_kill_time is not None else "",
        "burst_seconds": burst_seconds,
    }


def score_all_sessions(df):
    """Returns a DataFrame, one row per session_id, with behavioral signal columns."""
    results = []
    for session_id, session_df in df.groupby("session_id"):
        signals = score_session(session_df)
        signals["session_id"] = session_id
        results.append(signals)
    return pd.DataFrame(results)
