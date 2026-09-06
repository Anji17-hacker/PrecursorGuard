#!/usr/bin/env python3
"""
PrecursorGuard Live Detection Dashboard

Displays live endpoint telemetry produced by the Windows watcher.

Detection paths:

    BYOVD / EDR-killer sequence
    Ransomware behavioral detection
    BYOVD burst detection

Primary live alert source:

    reports/live_alerts.csv
"""

import os
import sys

import pandas as pd
import streamlit as st


# ---------------------------------------------------------------------
# Project root
# ---------------------------------------------------------------------

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


# ---------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------

ALERTS_PATH = os.path.join(
    PROJECT_ROOT,
    "reports",
    "live_alerts.csv",
)


# ---------------------------------------------------------------------
# Streamlit configuration
# ---------------------------------------------------------------------

st.set_page_config(
    page_title="PrecursorGuard",
    page_icon="🛡️",
    layout="wide",
)


# ---------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------

st.title(
    "PrecursorGuard — BYOVD / Ransomware Detection Dashboard"
)

st.caption(
    "Live endpoint telemetry → behavioral detection → risk scoring → alerting"
)


# ---------------------------------------------------------------------
# Refresh
# ---------------------------------------------------------------------

if st.button("🔄 Refresh Live Data"):
    st.rerun()


# ---------------------------------------------------------------------
# Load live alerts
# ---------------------------------------------------------------------

if not os.path.exists(ALERTS_PATH):

    st.warning(
        "No live alerts have been generated yet."
    )

    st.info(
        "Start the Windows watcher with:"
    )

    st.code(
        "python agent\\live_watcher.py --mode windows",
        language="powershell",
    )

    st.stop()


try:

    alerts = pd.read_csv(
        ALERTS_PATH
    )

except Exception as exc:

    st.error(
        f"Unable to read live alerts: {exc}"
    )

    st.stop()


# ---------------------------------------------------------------------
# Empty check
# ---------------------------------------------------------------------

if alerts.empty:

    st.warning(
        "The live alert file exists, but it contains no alerts yet."
    )

    st.stop()


# ---------------------------------------------------------------------
# Normalize boolean columns
# ---------------------------------------------------------------------

BOOLEAN_COLUMNS = [
    "alert",
    "ransomware_alert",
    "burst_alert",
    "final_alert",
]


for column in BOOLEAN_COLUMNS:

    if column in alerts.columns:

        alerts[column] = (
            alerts[column]
            .astype(str)
            .str.lower()
            .isin(
                [
                    "true",
                    "1",
                    "yes",
                ]
            )
        )


# ---------------------------------------------------------------------
# Normalize numeric columns
# ---------------------------------------------------------------------

NUMERIC_COLUMNS = [
    "risk_score",
    "ransomware_behavior_score",
    "burst_score",
    "file_create_count",
    "precursor_command_count",
]


for column in NUMERIC_COLUMNS:

    if column in alerts.columns:

        alerts[column] = pd.to_numeric(
            alerts[column],
            errors="coerce",
        ).fillna(0)


# ---------------------------------------------------------------------
# Calculate final display score
# ---------------------------------------------------------------------

score_columns = []

for column in [
    "risk_score",
    "ransomware_behavior_score",
    "burst_score",
]:

    if column in alerts.columns:
        score_columns.append(column)


if score_columns:

    alerts["final_detection_score"] = alerts[
        score_columns
    ].max(axis=1)

else:

    alerts["final_detection_score"] = 0.0


# ---------------------------------------------------------------------
# Page metrics
# ---------------------------------------------------------------------

latest = alerts.iloc[-1]

total_alerts = len(alerts)

ransomware_alerts = (
    int(alerts["ransomware_alert"].sum())
    if "ransomware_alert" in alerts.columns
    else 0
)

burst_alerts = (
    int(alerts["burst_alert"].sum())
    if "burst_alert" in alerts.columns
    else 0
)

highest_score = float(
    alerts["final_detection_score"].max()
)


col1, col2, col3, col4 = st.columns(4)


col1.metric(
    "Live Alerts",
    total_alerts,
)

col2.metric(
    "Ransomware Alerts",
    ransomware_alerts,
)

col3.metric(
    "BYOVD Burst Alerts",
    burst_alerts,
)

col4.metric(
    "Highest Detection Score",
    f"{highest_score:.3f}",
)


# ---------------------------------------------------------------------
# Latest detection
# ---------------------------------------------------------------------

st.subheader("🚨 Latest Detection")


latest_score = float(
    latest["final_detection_score"]
)


if latest_score >= 0.8:

    st.error(
        f"High-risk behavior detected — score {latest_score:.3f}"
    )

elif latest_score >= 0.7:

    st.warning(
        f"Suspicious behavior detected — score {latest_score:.3f}"
    )

else:

    st.info(
        f"Detection recorded — score {latest_score:.3f}"
    )


# ---------------------------------------------------------------------
# Detection details
# ---------------------------------------------------------------------

detail_col1, detail_col2 = st.columns(2)


with detail_col1:

    st.write("### Ransomware Behavior")

    ransomware_score = float(
        latest.get(
            "ransomware_behavior_score",
            0.0,
        )
    )

    file_count = int(
        latest.get(
            "file_create_count",
            0,
        )
    )

    st.metric(
        "Ransomware Behavior Score",
        f"{ransomware_score:.3f}",
    )

    st.metric(
        "Files Created",
        file_count,
    )

    if latest.get(
        "ransomware_alert",
        False,
    ):

        st.error(
            "Ransomware behavioral threshold crossed"
        )

    else:

        st.success(
            "Ransomware behavioral threshold not crossed"
        )


with detail_col2:

    st.write("### BYOVD / EDR Behavior")

    risk_score = float(
        latest.get(
            "risk_score",
            0.0,
        )
    )

    burst_score = float(
        latest.get(
            "burst_score",
            0.0,
        )
    )

    st.metric(
        "Sequence Risk Score",
        f"{risk_score:.3f}",
    )

    st.metric(
        "BYOVD Burst Score",
        f"{burst_score:.3f}",
    )


# ---------------------------------------------------------------------
# Latest event
# ---------------------------------------------------------------------

st.subheader("Latest Alert Record")

st.dataframe(
    pd.DataFrame(
        [latest]
    ),
    use_container_width=True,
)


# ---------------------------------------------------------------------
# Alert history
# ---------------------------------------------------------------------

st.subheader("Live Alert History")

display_columns = [
    "timestamp",
    "final_detection_score",
    "risk_score",
    "ransomware_behavior_score",
    "file_create_count",
    "burst_score",
    "ransomware_alert",
    "burst_alert",
    "final_alert",
]


available_columns = [
    column
    for column in display_columns
    if column in alerts.columns
]


history = alerts[
    available_columns
].sort_values(
    "timestamp",
    ascending=False,
)


st.dataframe(
    history,
    use_container_width=True,
)


# ---------------------------------------------------------------------
# Detection explanation
# ---------------------------------------------------------------------

st.subheader("How PrecursorGuard Detected It")

st.markdown(
    """
**Ransomware behavioral detection**

PrecursorGuard watches for a rapid burst of file-creation activity
associated with ransomware-style mass file modification.

**BYOVD detection**

The system independently evaluates suspicious driver loading,
privilege escalation, security-process termination, and precursor
commands.

**Final decision**

The dashboard presents the strongest active detection signal rather
than hiding a ransomware alert behind the older sequence score.
"""
)


# ---------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------

st.caption(
    "PrecursorGuard — live detection / explainable risk scoring"
)