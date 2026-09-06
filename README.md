# PrecursorGuard

Early-stage BYOVD / EDR-killer detection and automated ransomware
investigation platform. Detects the pre-encryption attack stage
(vulnerable driver load -> privilege escalation -> security software
kill -> recovery-disabling commands), not encryption itself.

## Project layout

```
agent/       Live event collector — real-time detection (simulated + real Windows source)
scripts/     One-off tooling — EVTX -> CSV converter, LOLDrivers reference builder
data/        Reference data (LOLDrivers) + raw/processed captured sessions
detection/   Rule Engine + Behavioral Engine + Precursor Engine + batch pipeline
scoring/     Dynamic risk score (weights/threshold in config/settings.py)
ml/          Machine learning layer — Random Forest / Logistic Regression / Gradient Boosting
response/    Alerts, notifications (stub), PDF forensic report generator
             (deliberately no auto-remediation — see response/alerts.py docstring)
dashboard/   Three dashboards, same underlying reports/ data:
               dashboard/app.py       Streamlit — live agent monitor (reports/live_alerts.csv)
               dashboard/web/app.py   Flask + custom HTML/CSS/JS — full investigation
                                      console: attack-chain visualization, alerts table,
                                      session timeline, MITRE map, detector comparison,
                                      PDF report download
               dashboard/web/app.py   -> /neon route — glass-card/neon SOC console (same
                                      backend, real /api/live + /api/mitre_summary data,
                                      not the hardcoded demo numbers it started as)
config/      Every tunable value in one place (weights, threshold, window, watchlist)
tests/       pytest unit tests for scoring, detection, and the live agent
docs/        Architecture notes + running decisions log for the paper
```

## Setup (one time)

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Run the whole thing (offline demo, no Windows VM needed)

```bash
# 1. Generate safe synthetic attack + benign sessions (all 7 scenario types,
#    including unknown_driver_attack and partial_attack — see docs/DECISIONS.md)
python detection/simulate_harness.py --sessions 150 --profile challenge --seed 100 --out data/processed/labeled_sessions.csv
python detection/simulate_harness.py --sessions 50 --profile challenge --seed 999 --out data/processed/challenge_sessions.csv

# 2. Run the batch hybrid detection pipeline (repeat --mode for rule_only / ml_only,
#    and swap --sessions for challenge_sessions.csv + reports/challenge_<mode>.csv
#    to reproduce the unseen-data evaluation)
python detection/pipeline.py --sessions data/processed/labeled_sessions.csv \
    --reference data/loldrivers_reference.csv --out reports/hybrid.csv --mode hybrid

# 3. Train and compare the ML models
python ml/train_model.py

# 4. Watch a live-streamed attack get caught in real time (no VM needed)
python agent/live_watcher.py --mode simulated --scenario attack

# 5a. Launch the Streamlit live-agent dashboard
streamlit run dashboard/app.py

# 5b. Launch the full investigation console (recommended for demos/viva)
python dashboard/web/app.py
# -> open http://127.0.0.1:5050            (investigation console)
# -> open http://127.0.0.1:5050/neon       (live neon SOC console)
```

Or run all of the above in one shot:

```bash
bash run_demo.sh
```

## Run the tests

```bash
pytest tests/ -v
```

## Run it for real, on your Windows VM

1. Follow `docs/architecture.md` and Part 2 of `PrecursorGuard_Complete_Project_Guide.docx`
   to install Sysmon and export logs.
2. Batch mode: `python scripts/evtx_to_csv.py sysmon_export.evtx data/raw/session_001.csv`,
   then feed it through `detection/pipeline.py`.
3. Live mode (Administrator PowerShell, `pip install pywin32` first):
   `python agent/live_watcher.py --mode windows`

## What changed since the last version — read this before your viva

The detector used to be, in effect, signature-only at its highest-confidence
path: the risk-score weights gave a LOLDrivers hash match 40% of the total
score, and BYOVD burst detection *required* a hash match before it would
fire at all. Tested against a synthetic `unknown_driver_attack` scenario
(the exact chain — driver load → privilege escalation → EDR kill — but
using a driver hash not yet in the LOLDrivers list), it had **0% recall**.
That directly contradicted the project's own thesis: catching attacker
*behavior* before encryption, not just known-bad hashes.

Full root-cause writeup and every change made: `docs/DECISIONS.md`
(entries dated 2026-09-02). Short version:
- Risk weights rebalanced to 0.30 / 0.30 / 0.30 / 0.10 (driver / priv-esc /
  kill / precursor) — any two of the three primary signals now cross the
  0.6 alert threshold without needing a hash match.
- Burst detection no longer requires a hash match — privilege escalation +
  security-process kill inside the burst window is the signal.
- The ML feature set was missing `rule_match` entirely — added it, and
  retrained on all 7 scenario types instead of 3.
- Re-verified on a completely fresh, unseen-seed synthetic dataset:
  hybrid = 100% precision / 100% recall; rule-only = 100% / 80% (still
  correctly misses the zero-day-driver case — this is the evidence for
  "hybrid beats signature-only" in your paper); ml-only = 100% / 100%.

## What's NOT included, on purpose

No auto-remediation (kill/quarantine a process automatically) — see
`response/alerts.py`'s docstring for why. No notification integration
(Slack/email) — `response/notifications.py` is a documented stub.
Extending either is a deliberate scope change: log it in
`docs/DECISIONS.md` and get your faculty guide's sign-off first.
