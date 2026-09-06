#!/usr/bin/env python3
"""PrecursorGuard end-to-end batch detection pipeline.

Hybrid mode now has two independent detection paths:
    1. Existing sequence-based risk score.
    2. Collapsed/BYOVD burst score for driver + privilege escalation +
       security-process termination inside the configured burst window.

Final hybrid alert = sequence alert OR burst alert.
"""
import argparse
import os
import sys
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from detection.rule_detector import load_reference, flag_driver_loads
    from detection.behavioral_detector import score_all_sessions as behavioral_scores
    from detection.precursor_detector import score_all_sessions as precursor_scores
    from scoring.risk_score import (
        compute_risk_score,
        compute_burst_score,
        is_alert,
        ALERT_THRESHOLD,
        BURST_WINDOW_SECONDS,
    )
except ImportError:
    from rule_detector import load_reference, flag_driver_loads
    from behavioral_detector import score_all_sessions as behavioral_scores
    from precursor_detector import score_all_sessions as precursor_scores
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scoring"))
    from risk_score import compute_risk_score, compute_burst_score, is_alert, ALERT_THRESHOLD, BURST_WINDOW_SECONDS


def build_session_table(sessions_path, reference_path):
    df = pd.read_csv(sessions_path)
    df["event_id"] = df["event_id"].astype(int)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    known_bad = load_reference(reference_path)
    driver_loads = flag_driver_loads(df, known_bad)
    rule_by_session = driver_loads.groupby("session_id")["rule_match"].any().reset_index()

    behavioral = behavioral_scores(df)
    precursor = precursor_scores(df)
    labels = df.groupby("session_id")["label"].first().reset_index()

    # Scenario is optional so old datasets remain compatible.
    scenario = df.groupby("session_id")["scenario"].first().reset_index() if "scenario" in df.columns else pd.DataFrame({"session_id": df["session_id"].unique(), "scenario": "unknown"})

    session_start = df.groupby("session_id")["timestamp"].min().reset_index(name="session_start")
    session_end = df.groupby("session_id")["timestamp"].max().reset_index(name="session_end")

    merged = (labels.merge(scenario, on="session_id", how="left")
                    .merge(rule_by_session, on="session_id", how="left")
                    .merge(behavioral, on="session_id", how="left")
                    .merge(precursor, on="session_id", how="left")
                    .merge(session_start, on="session_id", how="left")
                    .merge(session_end, on="session_id", how="left"))

    merged["rule_match"] = merged["rule_match"].fillna(False).astype(bool)
    merged["precursor_command_count"] = merged["precursor_command_count"].fillna(0)
    merged["burst_seconds"] = pd.to_numeric(merged["burst_seconds"], errors="coerce")
    return merged


def _first_time(*values):
    parsed = [pd.to_datetime(v, errors="coerce") for v in values if v not in (None, "", pd.NaT)]
    parsed = [v for v in parsed if not pd.isna(v)]
    return min(parsed) if parsed else pd.NaT


def apply_hybrid_scoring(session_table):
    rows = []
    for _, r in session_table.iterrows():
        risk_score, sub_scores = compute_risk_score(
            driver_reputation_flag=r["rule_match"],
            privilege_escalation_flag=r.get("privilege_escalation_flag", 0),
            process_kill_flag=r.get("security_process_killed", 0),
            precursor_command_count=r.get("precursor_command_count", 0),
        )

        burst_score = compute_burst_score(
            driver_reputation_flag=r["rule_match"],
            privilege_escalation_flag=r.get("privilege_escalation_flag", 0),
            process_kill_flag=r.get("security_process_killed", 0),
            burst_seconds=r.get("burst_seconds"),
        )
        sequence_alert = is_alert(risk_score)
        burst_alert = burst_score >= 1.0
        final_alert = sequence_alert or burst_alert

        driver_time = _first_time(r.get("driver_load_time"))
        priv_time = _first_time(r.get("privilege_escalation_time"))
        kill_time = _first_time(r.get("security_process_kill_time"))

        # Approximate earliest explainable detection point for the hybrid detector.
        # Sequence path reaches ALERT_THRESHOLD once enough signals (driver
        # reputation and/or privilege escalation and/or process kill) have
        # fired; burst path reaches 1.0 when the priv-esc+kill pair completes
        # inside the burst window. Neither path requires a driver-hash match
        # any more (see scoring/risk_score.py), so the detection-time signals
        # considered here must not assume rule_match is what fired the alert.
        detection_time = pd.NaT
        detection_reason = ""
        if sequence_alert:
            detection_time = _first_time(driver_time, priv_time, kill_time)
            detection_reason = "sequence"
        if burst_alert:
            burst_detection_time = _first_time(kill_time)
            if pd.isna(detection_time) or (not pd.isna(burst_detection_time) and burst_detection_time < detection_time):
                detection_time = burst_detection_time
                detection_reason = "burst"

        attack_start = driver_time
        lead_time = None
        if not pd.isna(detection_time) and not pd.isna(attack_start):
            lead_time = (detection_time - attack_start).total_seconds()

        rows.append({
            "session_id": r["session_id"],
            "scenario": r.get("scenario", "unknown"),
            "ground_truth_label": r["label"],
            "rule_match": r["rule_match"],
            "privilege_escalation_flag": r.get("privilege_escalation_flag", 0),
            "security_process_killed": r.get("security_process_killed", 0),
            "precursor_command_count": r.get("precursor_command_count", 0),
            "burst_seconds": r.get("burst_seconds"),
            "burst_window_seconds": BURST_WINDOW_SECONDS,
            **{f"subscore_{k}": v for k, v in sub_scores.items()},
            "risk_score": round(risk_score, 3),
            "sequence_alert": sequence_alert,
            "burst_score": burst_score,
            "burst_alert": burst_alert,
            "alert": final_alert,
            "detection_reason": detection_reason,
            "attack_start": attack_start.isoformat() if not pd.isna(attack_start) else "",
            "detection_time": detection_time.isoformat() if not pd.isna(detection_time) else "",
            "detection_delay_seconds": round(lead_time, 3) if lead_time is not None else None,
        })
    return pd.DataFrame(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sessions", default="data/processed/labeled_sessions.csv")
    parser.add_argument("--reference", default="data/loldrivers_reference.csv")
    parser.add_argument("--out", default="reports/alerts.csv")
    parser.add_argument("--mode", choices=["hybrid", "rule_only", "ml_only"], default="hybrid")
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    session_table = build_session_table(args.sessions, args.reference)

    if args.mode == "rule_only":
        alerts = session_table.copy()
        alerts["ground_truth_label"] = alerts["label"]
        alerts["alert"] = alerts["rule_match"]
        alerts["risk_score"] = alerts["rule_match"].astype(float)
        alerts["sequence_alert"] = alerts["alert"]
        alerts["burst_score"] = 0.0
        alerts["burst_alert"] = False
    elif args.mode == "ml_only":
        from ml.features import build_feature_matrix
        import joblib
        model = joblib.load("ml/models/model.joblib")
        X, _ = build_feature_matrix(session_table)
        proba = model.predict_proba(X)[:, 1]
        alerts = session_table.copy()
        alerts["ground_truth_label"] = alerts["label"]
        alerts["risk_score"] = proba
        alerts["alert"] = proba >= ALERT_THRESHOLD
        alerts["sequence_alert"] = False
        alerts["burst_score"] = 0.0
        alerts["burst_alert"] = False
    else:
        alerts = apply_hybrid_scoring(session_table)

    alerts.to_csv(args.out, index=False)
    n_alerts = int(alerts["alert"].sum())
    n_true_attacks = int((alerts["ground_truth_label"] == "attack").sum())
    print(f"Mode: {args.mode}")
    print(f"Sessions scored: {len(alerts)} | Alerts raised: {n_alerts} | True attack sessions: {n_true_attacks}")
    if args.mode == "hybrid":
        print(f"Burst alerts: {int(alerts['burst_alert'].sum())}")
    print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()
