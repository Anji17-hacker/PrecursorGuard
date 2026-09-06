#!/usr/bin/env python3
"""
ml/features.py

Phase 10 of the roadmap: turns the per-session signal table (produced
by detection/pipeline.py's build_session_table) into a fixed-size
feature matrix for scikit-learn.

Kept separate from the training script so it can be unit-tested and
reused by both training and inference (detection/pipeline.py --mode ml_only).
"""
import numpy as np

FEATURE_COLUMNS = [
    "rule_match",
    "privilege_escalation_flag",
    "security_process_killed",
    "precursor_command_count",
    "time_since_driver_load",
    "burst_seconds",
]
# NOTE: rule_match (LOLDrivers hash match) was missing from this list
# entirely. Without it the model has no way to see "known-bad driver" at
# all, so it can't catch a partial_attack session (known-bad driver ->
# privilege escalation -> recovery-disable command, but no EDR-process
# kill because the attacker's kill attempt failed/was blocked) — every
# feature it *did* have (privilege_escalation_flag, precursor_command_count)
# looked identical to a benign_admin session on that column alone, and
# security_process_killed / burst_seconds were 0/NaN just like benign
# traffic. Adding rule_match gives the model the one signal that actually
# distinguishes "known-bad driver present" from ordinary admin activity.


def build_feature_matrix(session_table):
    """
    session_table: DataFrame with at least FEATURE_COLUMNS present.
    Returns (X, session_ids) where X is a numpy array, session_ids aligns row-for-row.
    """
    df = session_table.copy()
    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0
    df[FEATURE_COLUMNS] = df[FEATURE_COLUMNS].apply(pd_to_numeric_safe)

    X = df[FEATURE_COLUMNS].to_numpy(dtype=float)
    session_ids = df["session_id"].tolist()
    return X, session_ids


def pd_to_numeric_safe(col):
    """rule_match arrives as a bool column; everything else numeric. Coerce
    all of them to float safely (bools -> 0.0/1.0, NaN -> 0.0)."""
    import pandas as pd
    return pd.to_numeric(col, errors="coerce").fillna(0).astype(float)


def build_labels(session_table):
    return np.where(session_table["label"] == "attack", 1, 0)
