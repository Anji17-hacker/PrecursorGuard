#!/usr/bin/env python3
"""
agent/session_tracker.py

The core real-time detection engine for PrecursorGuard.

The tracker watches ONE Windows host's live Sysmon event stream
and recomputes detection after every event.

Detection paths:

1. Sequence-based detection
   - Suspicious driver
   - Privilege escalation
   - Security-process termination
   - Precursor commands

2. BYOVD burst detection
   - Suspicious driver
   - Privilege escalation
   - Security-process termination
   - All within a short time window

3. Ransomware behavior detection
   - Rapid file creation
   - Suspicious ransomware-like extensions
   - Ransom-note indicators

The final alert is:

    Sequence Alert
        OR
    BYOVD Burst Alert
        OR
    Ransomware Behavior Alert
"""

import re
import sys
import os

from collections import deque
from datetime import datetime, timedelta, timezone


# ---------------------------------------------------------------------
# Allow imports from project root
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
# Project imports
# ---------------------------------------------------------------------

from scoring.risk_score import (
    compute_risk_score,
    compute_burst_score,
    compute_ransomware_behavior_score,
    is_ransomware_alert,
    is_alert,
    ALERT_THRESHOLD,
)

from detection.precursor_detector import (
    matches_precursor_pattern
)

from config.settings import (
    SECURITY_PROCESS_NAMES,
    WINDOW_SECONDS,
    BURST_WINDOW_SECONDS,
)


# ---------------------------------------------------------------------
# Ransomware file indicators
# ---------------------------------------------------------------------

SUSPICIOUS_RANSOMWARE_EXTENSIONS = {
    ".locked",
    ".encrypted",
    ".enc",
    ".crypt",
    ".crypto",
    ".lockbit",
    ".wncry",
    ".wannacry",
    ".ryk",
    ".ryuk",
    ".conti",
    ".akira",
    ".blackcat",
    ".clop",
}


RANSOM_NOTE_NAMES = {
    "readme.txt",
    "readme.html",
    "readme.hta",
    "decrypt.txt",
    "decrypt.html",
    "decrypt.hta",
    "recover.txt",
    "recover.html",
    "ransom.txt",
    "ransom.html",
    "how_to_decrypt.txt",
    "how_to_decrypt.html",
}


# ---------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------

def _basename(path):
    """
    Return lowercase filename portion of a Windows/Unix path.
    """

    if not isinstance(path, str) or not path:
        return ""

    return (
        path
        .replace("\\", "/")
        .split("/")[-1]
        .lower()
    )


def extract_sha256(hashes_field):
    """
    Extract SHA256 from a Sysmon hashes field.

    Example:

        SHA256=abcdef123456...

    Returns:

        lowercase SHA256 string
        or None
    """

    if not isinstance(hashes_field, str):
        return None

    match = re.search(
        r"SHA256=([0-9A-Fa-f]{64})",
        hashes_field
    )

    return (
        match.group(1).lower()
        if match
        else None
    )


# ---------------------------------------------------------------------
# HostStateTracker
# ---------------------------------------------------------------------

class HostStateTracker:
    """
    Tracks one monitored Windows endpoint.

    Feed events through:

        tracker.ingest(event)

    The tracker maintains a rolling time window.

    Three detection paths are evaluated:

        Sequence
        BYOVD Burst
        Ransomware Behavior
    """

    def __init__(
        self,
        known_bad_hashes,
        window_seconds=WINDOW_SECONDS,
        alert_threshold=ALERT_THRESHOLD,
    ):

        self.known_bad_hashes = known_bad_hashes

        # Normal rolling analysis window.
        self.window_seconds = window_seconds

        # Short BYOVD burst window.
        self.burst_window_seconds = (
            BURST_WINDOW_SECONDS
        )

        self.alert_threshold = alert_threshold

        # Stores:
        #
        #     (timestamp, event_dict)
        #
        self.events = deque()

        # Prevent repeated alerts while the same
        # rolling window remains in alert state.
        self.already_alerted_for_window = False

    # -----------------------------------------------------------------
    # Rolling window
    # -----------------------------------------------------------------

    def _prune(self, now):
        """
        Remove events outside the normal rolling window.
        """

        cutoff = (
            now
            - timedelta(
                seconds=self.window_seconds
            )
        )

        while (
            self.events
            and self.events[0][0] < cutoff
        ):
            self.events.popleft()

    # -----------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------

    def _recompute(self):
        """
        Recompute all detection paths from the current
        rolling event window.
        """

        # -------------------------------------------------------------
        # Existing sequence flags
        # -------------------------------------------------------------

        driver_reputation_flag = False
        privilege_escalation_flag = False
        process_kill_flag = False
        precursor_command_count = 0

        # -------------------------------------------------------------
        # Ransomware behavior counters
        # -------------------------------------------------------------

        file_create_count = 0
        suspicious_extension_count = 0
        ransom_note_count = 0

        # -------------------------------------------------------------
        # Event timestamps
        # -------------------------------------------------------------

        driver_load_time = None
        privilege_escalation_time = None
        process_kill_time = None

        # -------------------------------------------------------------
        # Inspect all events in rolling window
        # -------------------------------------------------------------

        for ts, ev in self.events:

            try:
                eid = int(
                    ev.get(
                        "event_id",
                        0
                    )
                )

            except (
                TypeError,
                ValueError
            ):
                eid = 0

            # =========================================================
            # EVENT ID 6 — DRIVER LOAD
            # =========================================================

            if eid == 6:

                sha = extract_sha256(
                    ev.get(
                        "hashes",
                        ""
                    )
                )

                if sha in self.known_bad_hashes:

                    driver_reputation_flag = True

                    if driver_load_time is None:

                        driver_load_time = ts

                    else:

                        driver_load_time = min(
                            driver_load_time,
                            ts
                        )

            # =========================================================
            # EVENT ID 1 — PROCESS CREATE
            # =========================================================

            elif eid == 1:

                integrity_level = str(
                    ev.get(
                        "integrity_level",
                        ""
                    )
                ).lower()

                parent_process = _basename(
                    ev.get(
                        "parent_process",
                        ""
                    )
                )

                command_line = str(
                    ev.get(
                        "command_line",
                        ""
                    )
                ).lower()

                # -----------------------------------------------------
                # Privilege escalation heuristic
                # -----------------------------------------------------

                interactive_parents = {
                    "explorer.exe",
                    "cmd.exe",
                    "powershell.exe",
                    "pwsh.exe",
                    "wscript.exe",
                    "cscript.exe",
                    "mshta.exe",
                    "rundll32.exe",
                    "regsvr32.exe",
                }

                suspicious_parent = (
                    parent_process
                    in interactive_parents
                )

                suspicious_command = any(
                    keyword in command_line
                    for keyword in (
                        "whoami /priv",
                        "token",
                        "privilege",
                        "seimpersonate",
                        "sedebug",
                        "seloaddriver",
                    )
                )

                if (
                    integrity_level == "system"
                    and (
                        suspicious_parent
                        or suspicious_command
                    )
                ):

                    privilege_escalation_flag = True

                    if privilege_escalation_time is None:

                        privilege_escalation_time = ts

                # -----------------------------------------------------
                # Existing precursor command detection
                # -----------------------------------------------------

                if matches_precursor_pattern(
                    ev.get(
                        "command_line",
                        ""
                    )
                ):

                    precursor_command_count += 1

            # =========================================================
            # EVENT ID 5 — PROCESS TERMINATED
            # =========================================================

            elif eid == 5:

                process_name = _basename(
                    ev.get(
                        "process_name",
                        ""
                    )
                )

                if (
                    process_name
                    in SECURITY_PROCESS_NAMES
                ):

                    process_kill_flag = True

                    if process_kill_time is None:

                        process_kill_time = ts

            # =========================================================
            # EVENT ID 11 — FILE CREATED
            #
            # Ransomware behavior telemetry
            # =========================================================

            elif eid == 11:

                target_filename = str(
                    ev.get(
                        "target_filename",
                        ""
                    )
                ).lower()

                if not target_filename:
                    continue

                # -----------------------------------------------------
                # Count file creation
                # -----------------------------------------------------

                file_create_count += 1

                # -----------------------------------------------------
                # Suspicious ransomware extension
                # -----------------------------------------------------

                for extension in (
                    SUSPICIOUS_RANSOMWARE_EXTENSIONS
                ):

                    if target_filename.endswith(
                        extension
                    ):

                        suspicious_extension_count += 1
                        break

                # -----------------------------------------------------
                # Ransom-note filename
                # -----------------------------------------------------

                filename_only = _basename(
                    target_filename
                )

                if filename_only in RANSOM_NOTE_NAMES:

                    ransom_note_count += 1

        # =============================================================
        # BYOVD BURST DURATION
        # =============================================================

        burst_duration = None

        if (
            driver_load_time is not None
            and privilege_escalation_time is not None
            and process_kill_time is not None
        ):

            burst_start = min(
                driver_load_time,
                privilege_escalation_time,
                process_kill_time,
            )

            burst_end = max(
                driver_load_time,
                privilege_escalation_time,
                process_kill_time,
            )

            burst_duration = (
                burst_end
                - burst_start
            ).total_seconds()

        # =============================================================
        # BYOVD BURST SCORE
        # =============================================================

        burst_score = compute_burst_score(
            driver_reputation_flag,
            privilege_escalation_flag,
            process_kill_flag,
            burst_duration,
            self.burst_window_seconds,
        )

        # =============================================================
        # EXISTING SEQUENCE SCORE
        # =============================================================

        risk_score, sub_scores = compute_risk_score(
            driver_reputation_flag,
            privilege_escalation_flag,
            process_kill_flag,
            precursor_command_count,
        )

        # =============================================================
        # RANSOMWARE BEHAVIOR SCORE
        # =============================================================

        ransomware_behavior_score = (
            compute_ransomware_behavior_score(
                file_create_count=file_create_count,
                suspicious_extension_count=(
                    suspicious_extension_count
                ),
                ransom_note_count=ransom_note_count,
            )
        )

        # =============================================================
        # ALERT DECISIONS
        # =============================================================

        sequence_alert = is_alert(
            risk_score,
            self.alert_threshold,
        )

        burst_alert = (
            burst_score >= 1.0
        )

        ransomware_alert = (
            is_ransomware_alert(
                ransomware_behavior_score
            )
        )

        # =============================================================
        # FINAL ALERT
        # =============================================================

        final_alert = (
            sequence_alert
            or burst_alert
            or ransomware_alert
        )

        # =============================================================
        # COMPLETE RESULT
        # =============================================================

        return {

            # ---------------------------------------------------------
            # Existing detection signals
            # ---------------------------------------------------------

            "driver_reputation_flag":
                driver_reputation_flag,

            "privilege_escalation_flag":
                privilege_escalation_flag,

            "process_kill_flag":
                process_kill_flag,

            "precursor_command_count":
                precursor_command_count,

            # ---------------------------------------------------------
            # Existing sequence scoring
            # ---------------------------------------------------------

            "sub_scores":
                sub_scores,

            "risk_score":
                round(
                    risk_score,
                    3
                ),

            # ---------------------------------------------------------
            # BYOVD burst detection
            # ---------------------------------------------------------

            "burst_score":
                round(
                    burst_score,
                    3
                ),

            "burst_duration":
                burst_duration,

            # ---------------------------------------------------------
            # Ransomware behavior
            # ---------------------------------------------------------

            "file_create_count":
                file_create_count,

            "suspicious_extension_count":
                suspicious_extension_count,

            "ransom_note_count":
                ransom_note_count,

            "ransomware_behavior_score":
                ransomware_behavior_score,

            # ---------------------------------------------------------
            # Separate alert paths
            # ---------------------------------------------------------

            "sequence_alert":
                sequence_alert,

            "burst_alert":
                burst_alert,

            "ransomware_alert":
                ransomware_alert,

            # ---------------------------------------------------------
            # Final combined decision
            # ---------------------------------------------------------

            "alert":
                final_alert,
        }

    # -----------------------------------------------------------------
    # Event ingestion
    # -----------------------------------------------------------------

    def ingest(self, event):
        """
        Ingest one live event.

        Required fields:

            event_id
            timestamp

        Returns the current detection result.

        result["new_alert"] is True only when the tracker
        transitions from non-alerting to alerting.
        """

        # -------------------------------------------------------------
        # Get timestamp
        # -------------------------------------------------------------

        ts = event["timestamp"]

        if isinstance(ts, str):

            ts = datetime.fromisoformat(
                ts
            )

        # If timestamp has no timezone,
        # treat it as UTC.

        if ts.tzinfo is None:

            ts = ts.replace(
                tzinfo=timezone.utc
            )

        # -------------------------------------------------------------
        # Add event
        # -------------------------------------------------------------

        self.events.append(
            (
                ts,
                event
            )
        )

        # -------------------------------------------------------------
        # Remove old events
        # -------------------------------------------------------------

        self._prune(ts)

        # -------------------------------------------------------------
        # Recompute detection
        # -------------------------------------------------------------

        result = self._recompute()

        # -------------------------------------------------------------
        # Determine NEW alert
        # -------------------------------------------------------------

        was_alerting = (
            self.already_alerted_for_window
        )

        result["new_alert"] = (
            result["alert"]
            and not was_alerting
        )

        self.already_alerted_for_window = (
            result["alert"]
        )

        # -------------------------------------------------------------
        # Add current timestamp
        # -------------------------------------------------------------

        result["timestamp"] = (
            ts.isoformat()
        )

        return result


# ---------------------------------------------------------------------
# End of file
# ---------------------------------------------------------------------
