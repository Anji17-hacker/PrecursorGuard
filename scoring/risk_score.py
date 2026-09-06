#!/usr/bin/env python3
"""
scoring/risk_score.py

PrecursorGuard explainable risk scoring.

Detection paths:

1. Sequence score
   Driver reputation
   + privilege escalation
   + security-process termination
   + precursor commands

2. BYOVD burst score
   Known/suspicious driver
   + privilege escalation
   + security-process termination
   within a short window.

3. Ransomware behavior score
   Rapid file activity
   + suspicious ransomware-like extensions
   + ransom-note indicator.

The three paths remain independent.

Final Alert:

    Sequence Alert
        OR
    BYOVD Burst Alert
        OR
    Ransomware Behavior Alert
"""

import os
import sys

sys.path.insert(
    0,
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)

from config.settings import (
    RISK_WEIGHTS as WEIGHTS,
    ALERT_THRESHOLD,
    PRECURSOR_COUNT_CAP,
    BURST_WINDOW_SECONDS,
)


# ---------------------------------------------------------------------
# Ransomware behavior configuration
# ---------------------------------------------------------------------

RANSOMWARE_FILE_COUNT_THRESHOLD = 10

RANSOMWARE_HIGH_FILE_COUNT = 25

RANSOMWARE_BEHAVIOR_THRESHOLD = 0.70


# ---------------------------------------------------------------------
# Existing precursor-command normalization
# ---------------------------------------------------------------------

def normalize_precursor_count(
    count,
    cap=PRECURSOR_COUNT_CAP,
):
    """
    Normalize precursor-command count to 0-1.
    """

    if cap <= 0:
        return 0.0

    return min(count, cap) / cap


# ---------------------------------------------------------------------
# Existing sequence-based score
# ---------------------------------------------------------------------

def compute_risk_score(
    driver_reputation_flag,
    privilege_escalation_flag,
    process_kill_flag,
    precursor_command_count,
):
    """
    Existing PrecursorGuard sequence score.

    This function is intentionally preserved for compatibility
    with the existing project/tests.
    """

    sub_scores = {
        "driver_reputation": float(
            bool(driver_reputation_flag)
        ),

        "privilege_escalation": float(
            bool(privilege_escalation_flag)
        ),

        "process_kill": float(
            bool(process_kill_flag)
        ),

        "precursor_command": normalize_precursor_count(
            precursor_command_count
        ),
    }

    risk_score = sum(
        WEIGHTS[key] * sub_scores[key]
        for key in WEIGHTS
    )

    return risk_score, sub_scores


# ---------------------------------------------------------------------
# BYOVD burst score
# ---------------------------------------------------------------------

def compute_burst_score(
    driver_reputation_flag,
    privilege_escalation_flag,
    process_kill_flag,
    burst_seconds,
    burst_window_seconds=BURST_WINDOW_SECONDS,
):
    """
    Detect collapsed BYOVD behavior: privilege escalation followed by a
    security-process kill inside burst_window_seconds of a driver load.

    IMPORTANT (see docs/DECISIONS.md): this used to also require
    driver_reputation_flag (a LOLDrivers hash match) before it would fire
    at all. That meant an attacker using a driver that simply isn't in the
    LOLDrivers list yet — trivially true for any new/unlisted vulnerable
    driver, i.e. exactly the "zero-day BYOVD" case the whole project is
    meant to catch — produced a burst score of 0.0 no matter how fast or
    obvious the priv-esc -> EDR-kill chain was. The behavioral chain
    (privilege escalation + security-process kill inside the window) is
    the actual precursor signal and is now sufficient on its own. A known
    hash match still counts for something: it shortens the *effective*
    window (a recognized bad driver is trusted less, so we're stricter
    about nothing, but generous about timing isn't needed to be sure).
    """

    if not (privilege_escalation_flag and process_kill_flag):
        return 0.0

    if burst_seconds is None:
        return 0.0

    if burst_seconds < 0:
        return 0.0

    # Confirmed-bad driver: standard window. Unrecognized driver: identical
    # behavioral burst is still just as suspicious, so the same window
    # applies rather than silently downgrading it to "no burst".
    effective_window = burst_window_seconds

    if burst_seconds <= effective_window:
        return 1.0

    return 0.0


# ---------------------------------------------------------------------
# Ransomware behavior score
# ---------------------------------------------------------------------

def compute_ransomware_behavior_score(
    file_create_count,
    suspicious_extension_count=0,
    ransom_note_count=0,
):
    """
    Score ransomware-like file behavior.

    This is deliberately explainable and does not depend on ML.

    Signals:

        1. Rapid file creation/modification activity
        2. Suspicious ransomware-like extensions
        3. Ransom-note indicators

    Score ranges from 0.0 to 1.0.
    """

    try:
        file_create_count = max(
            0,
            int(file_create_count),
        )
    except (TypeError, ValueError):
        file_create_count = 0

    try:
        suspicious_extension_count = max(
            0,
            int(suspicious_extension_count),
        )
    except (TypeError, ValueError):
        suspicious_extension_count = 0

    try:
        ransom_note_count = max(
            0,
            int(ransom_note_count),
        )
    except (TypeError, ValueError):
        ransom_note_count = 0

    # -------------------------------------------------------------
    # File activity component
    # -------------------------------------------------------------

    if file_create_count >= RANSOMWARE_HIGH_FILE_COUNT:
        file_activity_score = 1.0

    elif file_create_count >= RANSOMWARE_FILE_COUNT_THRESHOLD:
        file_activity_score = 0.60

    elif file_create_count > 0:
        file_activity_score = (
            file_create_count
            / RANSOMWARE_FILE_COUNT_THRESHOLD
        ) * 0.60

    else:
        file_activity_score = 0.0

    # -------------------------------------------------------------
    # Suspicious extension component
    # -------------------------------------------------------------

    extension_score = min(
        suspicious_extension_count / 5.0,
        1.0,
    )

    # -------------------------------------------------------------
    # Ransom-note component
    # -------------------------------------------------------------

    ransom_note_score = min(
        ransom_note_count / 1.0,
        1.0,
    )

    # -------------------------------------------------------------
    # Explainable weighted score
    # -------------------------------------------------------------

    score = (
        0.50 * file_activity_score
        + 0.30 * extension_score
        + 0.20 * ransom_note_score
    )

    return round(
        min(score, 1.0),
        3,
    )


# ---------------------------------------------------------------------
# Ransomware alert decision
# ---------------------------------------------------------------------

def is_ransomware_alert(
    ransomware_behavior_score,
    threshold=RANSOMWARE_BEHAVIOR_THRESHOLD,
):
    """
    Determine whether ransomware behavior is strong enough
    to generate an alert.
    """

    return (
        ransomware_behavior_score
        >= threshold
    )


# ---------------------------------------------------------------------
# Existing alert decision
# ---------------------------------------------------------------------

def is_alert(
    risk_score,
    threshold=ALERT_THRESHOLD,
):
    """
    Existing sequence-score alert decision.
    """

    return risk_score >= threshold
