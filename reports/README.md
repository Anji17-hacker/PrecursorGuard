# reports/

Output-only directory — no code lives here anymore (the PDF generator
moved to response/report_generator.py). This folder holds generated
artifacts only, all gitignored:

- alerts.csv — batch pipeline output (detection/pipeline.py)
- live_alerts.csv — real-time agent output (agent/live_watcher.py)
- *_report.pdf — per-session forensic reports (response/report_generator.py)
