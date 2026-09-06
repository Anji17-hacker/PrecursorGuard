# Decisions Log

Log every non-trivial design choice here as you make it, with a one-line
reason. You'll need this for the IEEE paper's Methodology section, and
it's much cheaper to write now than to reconstruct in week 6.

| Date | Decision | Reason |
|---|---|---|
| YYYY-MM-DD | Risk score weights: 0.4 / 0.3 / 0.2 / 0.1 (driver / priv-esc / kill / precursor) | Starting point — driver reputation weighted highest since it's the most specific signal; refine after evaluation |
| YYYY-MM-DD | Alert threshold: 0.6 | Starting point — tune during Phase 14 evaluation once precision/recall tradeoffs are visible |
| YYYY-MM-DD | Behavioral correlation window: 60 seconds | Matches the roadmap's stated "short time window" assumption for driver-load → kill correlation; revisit if real captures show longer/shorter real attacker dwell times |
| YYYY-MM-DD | Synthetic data over live malware for training/eval | Safety — no real exploitation code is run; documented explicitly as a limitation in the paper |
| 2026-09-02 | Risk score weights changed to 0.30 / 0.30 / 0.30 / 0.10 (driver / priv-esc / kill / precursor); burst score no longer requires a driver-hash match | Evaluation on the `unknown_driver_attack` scenario (known behavior chain, driver hash *not* yet in LOLDrivers) showed 0% recall under the original 0.4/0.3/0.2/0.1 weights + hash-gated burst logic — the detector was, in effect, signature-only for its highest-confidence path. Any two of the three primary signals now cross ALERT_THRESHOLD (0.30+0.30=0.60) without requiring a hash match, matching the project's stated goal of catching *behavior*, not just known-bad hashes. |
| 2026-09-02 | Added `rule_match` to the ML feature set (`ml/features.py`) | It was missing entirely, so the ML model had no signal for "known-bad driver present" and missed `partial_attack` sessions (driver + priv-esc + precursor command, no EDR kill) that rule/behavioral detection could catch. |
| 2026-09-02 | ML training data regenerated with `--profile challenge` (all 7 scenario types) instead of `baseline` (3 types) | The model was trained only on classic/collapsed-attack + benign-admin patterns and never saw partial/delayed/unknown-driver/benign-driver-admin examples, so it generalized poorly to them. Training on the full scenario mix (held-out test split via `train_test_split`) and validating separately against a freshly-seeded, fully unseen challenge set gives an honest generalization check instead of an unseen-scenario-type check. |
