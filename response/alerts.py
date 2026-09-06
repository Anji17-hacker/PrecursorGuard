#!/usr/bin/env python3
"""
response/alerts.py

Live alert persistence and console formatting for PrecursorGuard.

Supports:
- Original BYOVD / EDR-killer sequence score
- Ransomware behavioral score
- Ransomware alert
- Burst alert
- Final alert state
"""

import csv
import os
import sys


# ---------------------------------------------------------------------
# Project root
# ---------------------------------------------------------------------

sys.path.insert(
    0,
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)


# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------

from config.settings import LIVE_ALERTS_LOG_PATH


# ---------------------------------------------------------------------
# CSV schema
# ---------------------------------------------------------------------

ALERT_FIELDS = [
    "timestamp",

    # Original sequence detection
    "risk_score",
    "driver_reputation_flag",
    "privilege_escalation_flag",
    "process_kill_flag",
    "precursor_command_count",
    "alert",

    # Ransomware behavioral detection
    "file_create_count",
    "ransomware_behavior_score",
    "ransomware_alert",

    # BYOVD burst detection
    "burst_score",
    "burst_alert",

    # Final decision
    "final_alert",
]


# ---------------------------------------------------------------------
# Safe value helper
# ---------------------------------------------------------------------

def get_value(result, key, default=0):
    """
    Safely retrieve a value from the tracker result.
    """

    value = result.get(key, default)

    if value is None:
        return default

    return value


# ---------------------------------------------------------------------
# Persist live alert
# ---------------------------------------------------------------------

def log_alert(result, path=LIVE_ALERTS_LOG_PATH):
    """
    Append one live alert to the configured CSV file.

    The CSV is created automatically if it does not exist.
    """

    directory = os.path.dirname(path)

    if directory:
        os.makedirs(directory, exist_ok=True)

    write_header = not os.path.exists(path)

    row = {
        "timestamp": get_value(result, "timestamp", ""),
        "risk_score": get_value(result, "risk_score", 0.0),

        "driver_reputation_flag": get_value(
            result,
            "driver_reputation_flag",
            0,
        ),

        "privilege_escalation_flag": get_value(
            result,
            "privilege_escalation_flag",
            0,
        ),

        "process_kill_flag": get_value(
            result,
            "process_kill_flag",
            0,
        ),

        "precursor_command_count": get_value(
            result,
            "precursor_command_count",
            0,
        ),

        "alert": get_value(
            result,
            "alert",
            False,
        ),

        # Ransomware behavior
        "file_create_count": get_value(
            result,
            "file_create_count",
            0,
        ),

        "ransomware_behavior_score": get_value(
            result,
            "ransomware_behavior_score",
            0.0,
        ),

        "ransomware_alert": get_value(
            result,
            "ransomware_alert",
            False,
        ),

        # BYOVD burst
        "burst_score": get_value(
            result,
            "burst_score",
            0.0,
        ),

        "burst_alert": get_value(
            result,
            "burst_alert",
            False,
        ),

        # Final decision
        "final_alert": get_value(
            result,
            "final_alert",
            get_value(result, "new_alert", False),
        ),
    }

    with open(
        path,
        "a",
        newline="",
        encoding="utf-8",
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=ALERT_FIELDS,
        )

        if write_header:
            writer.writeheader()

        writer.writerow(row)


# ---------------------------------------------------------------------
# Console alert
# ---------------------------------------------------------------------

def format_alert_console(result):
    """
    Produce a human-readable alert block.

    Shows the actual ransomware score instead of incorrectly
    displaying only the old sequence score.
    """

    risk_score = float(
        get_value(result, "risk_score", 0.0)
    )

    ransomware_score = float(
        get_value(
            result,
            "ransomware_behavior_score",
            0.0,
        )
    )

    burst_score = float(
        get_value(
            result,
            "burst_score",
            0.0,
        )
    )

    final_score = max(
        risk_score,
        ransomware_score,
        burst_score,
    )

    lines = [
        "!" * 70,
        f"ALERT — PrecursorGuard detection score {final_score:.3f}",
        "!" * 70,
        "",
        "Sequence Detection:",
        f"  risk_score:              {risk_score:.3f}",
        f"  driver_reputation:       {get_value(result, 'driver_reputation_flag', 0)}",
        f"  privilege_escalation:    {get_value(result, 'privilege_escalation_flag', 0)}",
        f"  process_kill:             {get_value(result, 'process_kill_flag', 0)}",
        f"  precursor_commands:       {get_value(result, 'precursor_command_count', 0)}",
        "",
        "Ransomware Behavior:",
        f"  file_create_count:        {get_value(result, 'file_create_count', 0)}",
        f"  ransomware_score:         {ransomware_score:.3f}",
        f"  ransomware_alert:         {get_value(result, 'ransomware_alert', False)}",
        "",
        "BYOVD Burst:",
        f"  burst_score:              {burst_score:.3f}",
        f"  burst_alert:              {get_value(result, 'burst_alert', False)}",
        "",
        f"  FINAL ALERT:              {get_value(result, 'final_alert', get_value(result, 'new_alert', False))}",
        "",
        "!" * 70,
    ]

    return "\n".join(lines)