#!/usr/bin/env python3
"""
precursor_detector.py

Phase 7 of the roadmap. Entropy spikes and mass file renames only show
up once encryption has already started, so they're not usable as
*precursor* signals. Instead this module looks for command-lines that
attackers run BEFORE encryption, while disabling recovery options —
these are simple, direct substring/regex matches, no ML needed.
"""
import re
import pandas as pd

PRECURSOR_PATTERNS = [
    re.compile(r"vssadmin(\.exe)?\s+delete\s+shadows", re.IGNORECASE),
    re.compile(r"wbadmin(\.exe)?\s+delete\s+catalog", re.IGNORECASE),
    re.compile(r"bcdedit(\.exe)?\s+/set\s+\{default\}\s+recoveryenabled\s+no", re.IGNORECASE),
    re.compile(r"\bnet(\.exe)?\s+stop\s+\S+", re.IGNORECASE),
    re.compile(r"\bsc(\.exe)?\s+stop\s+\S+", re.IGNORECASE),
]


def matches_precursor_pattern(command_line):
    if not isinstance(command_line, str) or not command_line:
        return False
    return any(p.search(command_line) for p in PRECURSOR_PATTERNS)


def count_precursor_commands(session_df):
    """Returns the count of Event ID 1 rows in this session whose command_line matches a precursor pattern."""
    process_creates = session_df[session_df["event_id"] == 1]
    return int(process_creates["command_line"].apply(matches_precursor_pattern).sum())


def score_all_sessions(df):
    results = []
    for session_id, session_df in df.groupby("session_id"):
        results.append({
            "session_id": session_id,
            "precursor_command_count": count_precursor_commands(session_df),
        })
    return pd.DataFrame(results)
