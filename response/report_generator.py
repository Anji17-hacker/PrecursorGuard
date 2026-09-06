#!/usr/bin/env python3
"""
response/report_generator.py

Phase 12-13 of the roadmap: given one detected/alerted session, auto-
generate a one-page forensic PDF report - session summary, risk score,
matched MITRE techniques, event timeline, and recommended response.
This is the "automated investigation" differentiator, so it needs no
manual steps beyond calling this function.

Requires: pip install fpdf2

Standalone usage:
    python response/report_generator.py <session_id>
(reads reports/alerts.csv and data/processed/labeled_sessions.csv)
"""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from fpdf import FPDF

RECOMMENDED_ACTIONS = [
    "Isolate the affected endpoint from the network immediately.",
    "Terminate the suspicious process tree identified in the timeline.",
    "Block the matched driver hash at the EDR/AV policy level.",
    "Verify shadow copies / backups were not deleted; restore from off-host backup if needed.",
    "Rotate credentials used on the affected host if privilege escalation is confirmed.",
]


class ReportPDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 14)
        self.cell(0, 10, "PrecursorGuard - Automated Forensic Report", ln=True)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(100, 100, 100)
        self.cell(0, 6, "Detect, then investigate - pre-encryption BYOVD/EDR-kill stage", ln=True)
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def section_title(self, title):
        self.set_font("Helvetica", "B", 12)
        self.set_fill_color(230, 230, 230)
        self.cell(0, 8, title, ln=True, fill=True)
        self.set_font("Helvetica", "", 10)
        self.ln(1)


def build_pdf_report(session_alert, session_events, mitre_map, out_path):
    pdf = ReportPDF()
    pdf.add_page()

    pdf.section_title("Session Summary")
    pdf.cell(0, 6, f"Session ID: {session_alert['session_id']}", ln=True)
    pdf.cell(0, 6, f"Risk score: {session_alert['risk_score']} (alert threshold: 0.6)", ln=True)
    pdf.cell(0, 6, f"Ground-truth label (evaluation only): {session_alert.get('ground_truth_label', 'n/a')}", ln=True)
    pdf.ln(3)

    pdf.section_title("Matched Signals")
    signal_cols = ["rule_match", "privilege_escalation_flag", "security_process_killed", "precursor_command_count"]
    for col in signal_cols:
        val = session_alert.get(col, 0)
        if val:
            pdf.cell(0, 6, f"- {col}: {val}", ln=True)
    pdf.ln(3)

    pdf.section_title("MITRE ATT&CK Mapping")
    for sig, tech in mitre_map.items():
        if session_alert.get(sig, 0):
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(0, 6, f"- {tech['technique_id']}: {tech['technique_name']}")
    pdf.ln(3)

    pdf.section_title("Event Timeline")
    pdf.set_font("Courier", "", 8)
    for _, row in session_events.iterrows():
        line = f"{row['timestamp']}  [EID {row['event_id']}]  {row.get('process_name') or row.get('image_loaded') or ''}  {row.get('command_line') or ''}"
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 5, line[:120])
    pdf.set_font("Helvetica", "", 10)
    pdf.ln(3)

    pdf.section_title("Recommended Response (not auto-remediated)")
    for action in RECOMMENDED_ACTIONS:
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 6, f"- {action}")

    pdf.output(out_path)
    return out_path


def main():
    import pandas as pd
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    session_id = sys.argv[1]

    alerts = pd.read_csv("reports/alerts.csv")
    sessions = pd.read_csv("data/processed/labeled_sessions.csv")
    with open("dashboard/mitre_mapping.json") as f:
        mitre_map = json.load(f)

    session_alert = alerts[alerts["session_id"] == session_id].iloc[0]
    session_events = sessions[sessions["session_id"] == session_id].sort_values("timestamp")

    out_path = f"reports/{session_id}_report.pdf"
    build_pdf_report(session_alert, session_events, mitre_map, out_path)
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
