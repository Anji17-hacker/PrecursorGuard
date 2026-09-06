#!/usr/bin/env python3
"""Safe synthetic evaluation harness for PrecursorGuard.

Creates three kinds of sessions:
  - classic BYOVD-like sequence (events spread over time)
  - collapsed/burst sequence (required signals within <=5 seconds)
  - benign administrative activity that resembles individual signals

No real driver is loaded, no security software is stopped, and no exploit
code is executed. Rows only imitate Sysmon-shaped telemetry.
"""
import argparse
import csv
import random
import uuid
from datetime import datetime, timedelta, timezone

KNOWN_BAD_HASH = "3b1e9a2c1f6d4e8a9c0b7f2d5e6a1c3b4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a"
SECURITY_PROCESSES = ["MsMpEng.exe", "fake_edr.exe", "SentinelAgent.exe"]
PRECURSOR_COMMANDS = [
    "vssadmin.exe delete shadows /all /quiet",
    "wbadmin.exe delete catalog -quiet",
    "bcdedit.exe /set {default} recoveryenabled no",
    "net.exe stop SentinelAgent",
    "sc.exe stop MsMpEng",
]
BENIGN_COMMANDS = [
    "notepad.exe C:\\Users\\demo\\notes.txt",
    "explorer.exe",
    "svchost.exe -k netsvcs",
    "chrome.exe --new-window",
]
FIELDNAMES = [
    "session_id", "scenario", "timestamp", "event_id", "process_name", "process_guid",
    "parent_process", "image_loaded", "driver_signed", "signer_name", "target_process",
    "command_line", "hashes", "integrity_level", "label",
]


def _row(session_id, scenario, ts, event_id, label, **kwargs):
    row = {fn: "" for fn in FIELDNAMES}
    row.update({"session_id": session_id, "scenario": scenario, "timestamp": ts.isoformat(), "event_id": event_id, "label": label})
    row.update(kwargs)
    return row


def _driver_row(session_id, scenario, ts, label="attack"):
    return _row(session_id, scenario, ts, "6", label,
                image_loaded="C:\\Windows\\System32\\drivers\\sample_driver_alpha.sys",
                hashes=f"SHA256={KNOWN_BAD_HASH}", driver_signed="true", signer_name="Sample Signer Inc")


def _priv_row(session_id, scenario, ts, label="attack"):
    return _row(session_id, scenario, ts, "1", label,
                process_name="C:\\Windows\\System32\\cmd.exe", process_guid=str(uuid.uuid4()),
                parent_process="C:\\Windows\\explorer.exe", command_line="cmd.exe /c whoami /priv",
                integrity_level="System")


def _kill_row(session_id, scenario, ts, label="attack"):
    return _row(session_id, scenario, ts, "5", label,
                process_name=random.choice(SECURITY_PROCESSES), process_guid=str(uuid.uuid4()))


def _precursor_row(session_id, scenario, ts, label="attack"):
    return _row(session_id, scenario, ts, "1", label,
                process_name="C:\\Windows\\System32\\vssadmin.exe", process_guid=str(uuid.uuid4()),
                parent_process="C:\\Windows\\System32\\cmd.exe", command_line=random.choice(PRECURSOR_COMMANDS),
                integrity_level="System")


def generate_classic_attack_session():
    """Classic sequence: driver -> privilege -> security-process kill -> precursor."""
    session_id = str(uuid.uuid4())
    t0 = datetime.now(timezone.utc)
    return [
        _driver_row(session_id, "classic_attack", t0),
        _priv_row(session_id, "classic_attack", t0 + timedelta(seconds=8)),
        _kill_row(session_id, "classic_attack", t0 + timedelta(seconds=25)),
        _precursor_row(session_id, "classic_attack", t0 + timedelta(seconds=50)),
    ]


def generate_collapsed_attack_session():
    """Collapsed sequence: required burst events all occur within 5 seconds."""
    session_id = str(uuid.uuid4())
    t0 = datetime.now(timezone.utc)
    return [
        _driver_row(session_id, "collapsed_attack", t0),
        _priv_row(session_id, "collapsed_attack", t0 + timedelta(seconds=1)),
        _kill_row(session_id, "collapsed_attack", t0 + timedelta(seconds=4)),
        # Safe/read-only stand-in for post-evasion precursor activity.
        _precursor_row(session_id, "collapsed_attack", t0 + timedelta(seconds=6)),
    ]


def generate_benign_admin_session():
    """Benign activity deliberately resembles individual attack signals."""
    session_id = str(uuid.uuid4())
    t0 = datetime.now(timezone.utc)
    rows = [
        _row(session_id, "benign_admin", t0, "6", "benign",
             image_loaded="C:\\Windows\\System32\\drivers\\usbhub3.sys",
             hashes="SHA256=" + uuid.uuid4().hex + uuid.uuid4().hex,
             driver_signed="true", signer_name="Microsoft Windows"),
        _row(session_id, "benign_admin", t0 + timedelta(seconds=10), "1", "benign",
             process_name="C:\\Windows\\System32\\cmd.exe", process_guid=str(uuid.uuid4()),
             parent_process="C:\\Windows\\explorer.exe", command_line="whoami /priv",
             integrity_level="System"),
        _row(session_id, "benign_admin", t0 + timedelta(seconds=30), "5", "benign",
             process_name="WindowsUpdate.exe", process_guid=str(uuid.uuid4())),
    ]
    for _ in range(2):
        rows.append(_row(session_id, "benign_admin", t0 + timedelta(seconds=random.randint(35, 60)), "1", "benign",
                         process_name=random.choice(["notepad.exe", "explorer.exe", "chrome.exe"]),
                         process_guid=str(uuid.uuid4()), parent_process="C:\\Windows\\explorer.exe",
                         command_line=random.choice(BENIGN_COMMANDS), integrity_level="Medium"))
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sessions", type=int, default=100, help="number of sessions PER SCENARIO")
    parser.add_argument("--out", default="data/processed/labeled_sessions.csv")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    random.seed(args.seed)
    all_rows = []
    for _ in range(args.sessions):
        all_rows.extend(generate_classic_attack_session())
        all_rows.extend(generate_collapsed_attack_session())
        all_rows.extend(generate_benign_admin_session())

    random.shuffle(all_rows)
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(all_rows)

    sessions = args.sessions * 3
    attacks = sum(1 for r in all_rows if r["label"] == "attack")
    print(f"Wrote {len(all_rows)} rows ({sessions} sessions) to {args.out}")
    print(f"Scenarios: classic_attack={args.sessions}, collapsed_attack={args.sessions}, benign_admin={args.sessions}")
    print(f"Row label split: attack={attacks}, benign={len(all_rows)-attacks}")


if __name__ == "__main__":
    main()
