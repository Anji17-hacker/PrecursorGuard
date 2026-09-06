#!/usr/bin/env bash
# run_demo.sh — runs the entire PrecursorGuard pipeline end to end on
# safe synthetic data. No Windows VM required.
set -e

echo "=== 1/5: Generating synthetic attack + benign sessions ==="
python3 detection/simulate_harness.py --sessions 100 --out data/processed/labeled_sessions.csv

echo
echo "=== 2/5: Running the batch hybrid detection pipeline ==="
python3 detection/pipeline.py --sessions data/processed/labeled_sessions.csv \
    --reference data/loldrivers_reference.csv --out reports/alerts.csv --mode hybrid

echo
echo "=== 3/5: Training and comparing ML models ==="
python3 ml/train_model.py

echo
echo "=== 4/5: Running unit tests ==="
python3 -m pytest tests/ -v

echo
echo "=== 5/5: Live-agent demo (simulated attack, real-time alert) ==="
python3 agent/live_watcher.py --mode simulated --scenario attack --speed 0.05

echo
echo "=== Done. Alerts written to reports/alerts.csv ==="
echo "Launch the dashboard with: streamlit run dashboard/app.py"
