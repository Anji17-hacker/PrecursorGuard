# Real-machine / real-sample testing checklist

Everything below is verified working on synthetic data (18/18 pytest,
batch pipeline, ML training, live agent, both dashboards, PDF report —
see the test log in the delivery message). These are the steps still
needed before pointing it at an actual malware sample.

## 1. Isolation — do this first, no exceptions

- Run the victim machine as an **isolated VM** (VirtualBox/VMware),
  **host-only or no networking**, no shared folders, no clipboard
  sharing.
- Take a **snapshot before every run** and revert after. Real
  ransomware/BYOVD samples do real damage to whatever they touch.
- Never run a live sample on your host OS, on a network-connected VM,
  or on anything with data you care about.

## 2. Get the real LOLDrivers reference

`data/loldrivers_reference.csv` currently ships with 2 sample rows
for the unit tests. It will **not** recognize a real vulnerable driver.

```bash
# on any machine with internet:
curl -o loldrivers_full.json https://www.loldrivers.io/api/drivers.json
python scripts/build_loldrivers_reference.py loldrivers_full.json data/loldrivers_reference.csv
```

Copy the resulting CSV into the VM.

## 3. Update the security-process watchlist

`config/settings.py` → `SECURITY_PROCESS_NAMES` only lists
`msmpeng.exe` (Windows Defender), `fake_edr.exe`, `sentinelagent.exe`.
If the VM runs a different AV/EDR, add its real process name(s) here
or `process_kill` will never fire for it.

## 4. Install Sysmon + pywin32 in the VM

```powershell
# Sysmon (with a config that logs event IDs 1, 5, 6, 10, 11, 13 —
# precursorguard-sysmon.xml in the repo root is a starting config)
sysmon64.exe -accepteula -i precursorguard-sysmon.xml

# in an Administrator PowerShell / terminal with the venv active:
pip install pywin32
```

## 5. Run live detection

```powershell
python agent/live_watcher.py --mode windows
```

Leave this running, then execute the sample. Alerts print to the
console in real time and log to `reports/live_alerts.csv`; open
`dashboard/app.py` (Streamlit) in a second window for a live view.

## 6. Batch mode (safer first step, if you don't want it live)

Detonate the sample, let it run briefly, stop it, then export and
score after the fact instead of watching live:

```powershell
# export the Sysmon channel to EVTX from Windows Event Viewer, then:
python scripts/evtx_to_csv.py sysmon_export.evtx data/raw/session_001.csv
python detection/pipeline.py --sessions data/raw/session_001.csv --reference data/loldrivers_reference.csv --out reports/real_run.csv --mode hybrid
python response/report_generator.py <session_id>   # from reports/real_run.csv
```

## 7. Known gaps to expect on a real sample

- `precursor_command` detection currently matches on exact commands
  seen in the synthetic data (`vssadmin`, `wbadmin`, `bcdedit`). Check
  `detection/precursor_detector.py` if your sample uses a different
  recovery-disabling command and extend the match list.
- The ML model was trained only on synthetic sessions (see
  `docs/DECISIONS.md`) — treat its verdict as a secondary signal on a
  real sample, not ground truth. The rule/behavioral/burst path is
  the one to trust and cite first, per `README.md`'s own guidance.
- `SECURITY_PROCESS_NAMES` and the LOLDrivers CSV are the two things
  most likely to cause a real run to under-alert if you skip steps 2–3.
