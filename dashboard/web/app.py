#!/usr/bin/env python3
"""
dashboard/web/app.py

Professional SOC-style web dashboard for PrecursorGuard (Flask +
vanilla HTML/CSS/JS — no build step, no external service required).

This is an ADDITIONAL dashboard alongside dashboard/app.py (Streamlit).
Use whichever you prefer; they read the same reports/ CSVs.

Run:
    pip install flask
    python dashboard/web/app.py
    -> open http://127.0.0.1:5050

Data sources (all produced by detection/pipeline.py, ml/train_model.py):
    reports/hybrid.csv, reports/rule_only.csv, reports/ml_only.csv
    reports/challenge_hybrid.csv, reports/challenge_rule_only.csv, reports/challenge_ml_only.csv
    data/processed/labeled_sessions.csv   (raw per-event rows, for timelines)
    dashboard/mitre_mapping.json
    ml/models/metrics.json
"""
import json
import os
import sys

import pandas as pd
from flask import Flask, jsonify, render_template, send_file, abort, request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

app = Flask(__name__, static_folder="static", template_folder="templates")

MODES = ["hybrid", "rule_only", "ml_only"]
DATASETS = {
    "baseline": {"reports_suffix": "", "sessions": "data/processed/labeled_sessions.csv"},
    "challenge": {"reports_suffix": "challenge_", "sessions": "data/processed/challenge_sessions.csv"},
}


def _path(*parts):
    return os.path.join(ROOT, *parts)


def load_alerts(mode, dataset):
    if mode not in MODES or dataset not in DATASETS:
        abort(404)
    suffix = DATASETS[dataset]["reports_suffix"]
    path = _path("reports", f"{suffix}{mode}.csv")
    if not os.path.exists(path):
        return pd.DataFrame()
    return pd.read_csv(path)


def load_sessions(dataset):
    path = _path(DATASETS[dataset]["sessions"])
    if not os.path.exists(path):
        return pd.DataFrame()
    df = pd.read_csv(path)
    return df


def load_mitre_map():
    with open(_path("dashboard", "mitre_mapping.json")) as f:
        return json.load(f)


def load_ml_metrics():
    path = _path("ml", "models", "metrics.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def severity_of(row):
    score = row.get("risk_score", 0) or 0
    if row.get("burst_alert"):
        return "critical"
    if score >= 0.85:
        return "critical"
    if score >= 0.6:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/neon")
def neon():
    return render_template("neon.html")


@app.route("/api/live")
def api_live():
    """Rows appended by agent/live_watcher.py while it's running against
    a real or simulated event stream. Used by the neon dashboard's
    'Live Threat Risk' chart and activity feed — independent of the
    batch reports/<mode>.csv files used elsewhere on this page."""
    path = _path("reports", "live_alerts.csv")
    if not os.path.exists(path):
        return jsonify({"rows": [], "note": "no live_alerts.csv yet — run agent/live_watcher.py"})
    df = pd.read_csv(path).tail(100)
    rows = []
    for _, r in df.iterrows():
        rows.append({
            "timestamp": r.get("timestamp"),
            "risk_score": round(float(r.get("risk_score", 0) or 0), 3),
            "burst_alert": bool(r.get("burst_alert", False)),
            "final_alert": bool(r.get("final_alert", False)),
            "ransomware_alert": bool(r.get("ransomware_alert", False)),
            "driver_reputation_flag": bool(r.get("driver_reputation_flag", False)),
            "privilege_escalation_flag": bool(r.get("privilege_escalation_flag", False)),
            "process_kill_flag": bool(r.get("process_kill_flag", False)),
            "precursor_command_count": int(r.get("precursor_command_count", 0) or 0),
            "file_create_count": int(r.get("file_create_count", 0) or 0),
        })
    return jsonify({"rows": rows})


@app.route("/api/mitre_summary")
def api_mitre_summary():
    """% of alerted sessions in the chosen mode/dataset that trip each
    MITRE-mapped signal — powers the 'Attack Vectors (MITRE)' bars on
    the neon dashboard. Real hit-rates, not the fixed demo numbers the
    static mockup shipped with."""
    mode = request.args.get("mode", "hybrid")
    dataset = request.args.get("dataset", "baseline")
    df = load_alerts(mode, dataset)
    mitre_map = load_mitre_map()
    if df.empty or "alert" not in df.columns:
        return jsonify([])
    alerted = df[df["alert"] == True]
    n = len(alerted) or 1
    out = []
    for signal, tech in mitre_map.items():
        if signal not in alerted.columns:
            continue
        hits = int(alerted[signal].fillna(False).astype(bool).sum()) if alerted[signal].dtype != object \
            else int((alerted[signal].fillna(0).astype(float) > 0).sum())
        out.append({
            "signal": signal,
            "technique_id": tech.get("technique_id"),
            "technique_name": tech.get("technique_name"),
            "pct": round(100 * hits / n, 1),
        })
    return jsonify(out)


@app.route("/api/summary")
def api_summary():
    mode = request.args.get("mode", "hybrid")
    dataset = request.args.get("dataset", "baseline")
    df = load_alerts(mode, dataset)
    if df.empty:
        return jsonify({"error": "no data — run detection/pipeline.py first"}), 200

    total = len(df)
    alerts = int(df["alert"].sum())
    tp = int(((df["alert"] == True) & (df["ground_truth_label"] == "attack")).sum())
    fp = int(((df["alert"] == True) & (df["ground_truth_label"] != "attack")).sum())
    fn = int(((df["alert"] == False) & (df["ground_truth_label"] == "attack")).sum())
    tn = int(((df["alert"] == False) & (df["ground_truth_label"] != "attack")).sum())
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * precision * recall / (precision + recall)) if precision and recall else None

    by_scenario = (
        df.groupby("scenario")["alert"].agg(["count", "sum"]).reset_index()
        if "scenario" in df.columns else pd.DataFrame()
    )
    scenario_rows = [
        {"scenario": r["scenario"], "count": int(r["count"]), "alerted": int(r["sum"])}
        for _, r in by_scenario.iterrows()
    ] if not by_scenario.empty else []

    risk_bins = [0, 0, 0, 0, 0]  # 0-.2 .2-.4 .4-.6 .6-.8 .8-1
    if "risk_score" in df.columns:
        for v in df["risk_score"].fillna(0):
            idx = min(int(v * 5), 4)
            risk_bins[idx] += 1

    return jsonify({
        "mode": mode,
        "dataset": dataset,
        "total_sessions": total,
        "alerts_raised": alerts,
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "true_negative": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "by_scenario": scenario_rows,
        "risk_histogram": risk_bins,
    })


@app.route("/api/compare")
def api_compare():
    """Precision/recall for all three modes, on both datasets — the
    evidence that the hybrid approach beats rule-only / ML-only."""
    dataset = request.args.get("dataset", "baseline")
    out = {}
    for mode in MODES:
        df = load_alerts(mode, dataset)
        if df.empty:
            out[mode] = None
            continue
        tp = int(((df["alert"] == True) & (df["ground_truth_label"] == "attack")).sum())
        fp = int(((df["alert"] == True) & (df["ground_truth_label"] != "attack")).sum())
        fn = int(((df["alert"] == False) & (df["ground_truth_label"] == "attack")).sum())
        precision = tp / (tp + fp) if (tp + fp) else None
        recall = tp / (tp + fn) if (tp + fn) else None
        out[mode] = {"precision": precision, "recall": recall, "tp": tp, "fp": fp, "fn": fn}
    return jsonify(out)


@app.route("/api/alerts")
def api_alerts():
    mode = request.args.get("mode", "hybrid")
    dataset = request.args.get("dataset", "baseline")
    only_alerts = request.args.get("only_alerts", "true") == "true"
    df = load_alerts(mode, dataset)
    if df.empty:
        return jsonify([])
    if only_alerts:
        df = df[df["alert"] == True]
    df = df.sort_values("risk_score", ascending=False)

    rows = []
    for _, r in df.iterrows():
        rows.append({
            "session_id": r["session_id"],
            "scenario": r.get("scenario", "unknown"),
            "ground_truth_label": r.get("ground_truth_label"),
            "risk_score": round(float(r.get("risk_score", 0) or 0), 3),
            "alert": bool(r.get("alert", False)),
            "sequence_alert": bool(r.get("sequence_alert", False)),
            "burst_alert": bool(r.get("burst_alert", False)),
            "detection_reason": r.get("detection_reason", ""),
            "rule_match": bool(r.get("rule_match", False)),
            "privilege_escalation_flag": bool(r.get("privilege_escalation_flag", 0)),
            "security_process_killed": bool(r.get("security_process_killed", 0)),
            "precursor_command_count": int(r.get("precursor_command_count", 0) or 0),
            "detection_delay_seconds": r.get("detection_delay_seconds"),
            "severity": severity_of(r),
        })
    return jsonify(rows)


@app.route("/api/session/<session_id>")
def api_session(session_id):
    dataset = request.args.get("dataset", "baseline")
    mode = request.args.get("mode", "hybrid")
    alerts_df = load_alerts(mode, dataset)
    sessions_df = load_sessions(dataset)
    mitre_map = load_mitre_map()

    match = alerts_df[alerts_df["session_id"] == session_id]
    if match.empty:
        abort(404)
    alert_row = match.iloc[0].to_dict()

    events_df = sessions_df[sessions_df["session_id"] == session_id].sort_values("timestamp")
    events = []
    for _, e in events_df.iterrows():
        events.append({
            "timestamp": e.get("timestamp"),
            "event_id": int(e.get("event_id", 0)),
            "label": _event_label(e),
            "detail": _event_detail(e),
        })

    matched_techniques = []
    for signal, tech in mitre_map.items():
        if alert_row.get(signal):
            matched_techniques.append(tech)

    def clean(v):
        try:
            if pd.isna(v):
                return None
        except Exception:
            pass
        return v

    alert_row = {k: clean(v) for k, v in alert_row.items()}

    return jsonify({
        "alert": alert_row,
        "events": events,
        "mitre": matched_techniques,
    })


def _event_label(e):
    eid = int(e.get("event_id", 0))
    return {
        1: "Process created",
        5: "Process terminated",
        6: "Driver loaded",
        11: "File created",
    }.get(eid, f"Event ID {eid}")


def _event_detail(e):
    eid = int(e.get("event_id", 0))
    if eid == 6:
        return e.get("image_loaded", "")
    if eid == 1:
        cmd = e.get("command_line", "")
        return cmd if isinstance(cmd, str) else ""
    if eid == 5:
        return e.get("process_name", "")
    if eid == 11:
        return e.get("target_filename", "")
    return ""


@app.route("/api/report/<session_id>")
def api_report(session_id):
    dataset = request.args.get("dataset", "baseline")
    mode = request.args.get("mode", "hybrid")
    try:
        from response.report_generator import build_pdf_report
    except ImportError:
        return jsonify({"error": "fpdf2 not installed — run: pip install fpdf2"}), 500

    alerts_df = load_alerts(mode, dataset)
    sessions_df = load_sessions(dataset)
    mitre_map = load_mitre_map()

    match = alerts_df[alerts_df["session_id"] == session_id]
    if match.empty:
        abort(404)
    session_alert = match.iloc[0]
    session_events = sessions_df[sessions_df["session_id"] == session_id].sort_values("timestamp")

    out_dir = _path("reports")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{session_id}_report.pdf")
    build_pdf_report(session_alert, session_events, mitre_map, out_path)
    return send_file(out_path, as_attachment=True, download_name=f"PrecursorGuard_{session_id[:8]}_report.pdf")


@app.route("/api/ml_metrics")
def api_ml_metrics():
    metrics = load_ml_metrics()
    if metrics is None:
        return jsonify({"error": "no ml/models/metrics.json — run ml/train_model.py first"}), 200
    return jsonify(metrics)


if __name__ == "__main__":
    app.run(debug=True, port=5050)
