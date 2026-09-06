#!/usr/bin/env python3
"""Safe synthetic evaluation harness for PrecursorGuard.

Profiles:

baseline:
    - classic BYOVD-like sequence
    - collapsed/burst sequence
    - benign administrative activity

challenge:
    - all baseline scenarios
    - benign signed-driver administrative activity
    - partial attack
    - delayed attack
    - unknown-driver behavioral attack

No real driver is loaded, no security software is stopped, and no exploit
code is executed. Rows only imitate Sysmon-shaped telemetry.
"""

import argparse
import csv
import random
import uuid
from datetime import datetime, timedelta, timezone


# ---------------------------------------------------------------------
# Synthetic reference values
# ---------------------------------------------------------------------

KNOWN_BAD_HASH = (
    "3b1e9a2c1f6d4e8a9c0b7f2d5e6a1c3b4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a"
)

SECURITY_PROCESSES = [
    "MsMpEng.exe",
    "fake_edr.exe",
    "SentinelAgent.exe",
]

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
    "session_id",
    "scenario",
    "timestamp",
    "event_id",
    "process_name",
    "process_guid",
    "parent_process",
    "image_loaded",
    "driver_signed",
    "signer_name",
    "target_process",
    "command_line",
    "hashes",
    "integrity_level",
    "label",
]


# ---------------------------------------------------------------------
# Generic row builder
# ---------------------------------------------------------------------

def _row(session_id, scenario, ts, event_id, label, **kwargs):
    row = {fn: "" for fn in FIELDNAMES}

    row.update(
        {
            "session_id": session_id,
            "scenario": scenario,
            "timestamp": ts.isoformat(),
            "event_id": event_id,
            "label": label,
        }
    )

    row.update(kwargs)
    return row


# ---------------------------------------------------------------------
# Common synthetic event builders
# ---------------------------------------------------------------------

def _driver_row(session_id, scenario, ts, label="attack"):
    """Synthetic known-bad driver-load event."""

    return _row(
        session_id,
        scenario,
        ts,
        "6",
        label,
        image_loaded=(
            "C:\\Windows\\System32\\drivers\\sample_driver_alpha.sys"
        ),
        hashes=f"SHA256={KNOWN_BAD_HASH}",
        driver_signed="true",
        signer_name="Sample Signer Inc",
    )


def _priv_row(session_id, scenario, ts, label="attack"):
    """Synthetic privilege-escalation event."""

    return _row(
        session_id,
        scenario,
        ts,
        "1",
        label,
        process_name="C:\\Windows\\System32\\cmd.exe",
        process_guid=str(uuid.uuid4()),
        parent_process="C:\\Windows\\explorer.exe",
        command_line="cmd.exe /c whoami /priv",
        integrity_level="System",
    )


def _kill_row(session_id, scenario, ts, label="attack"):
    """Synthetic security-process termination event."""

    return _row(
        session_id,
        scenario,
        ts,
        "5",
        label,
        process_name=random.choice(SECURITY_PROCESSES),
        process_guid=str(uuid.uuid4()),
    )


def _precursor_row(session_id, scenario, ts, label="attack"):
    """Synthetic ransomware-precursor command event."""

    return _row(
        session_id,
        scenario,
        ts,
        "1",
        label,
        process_name="C:\\Windows\\System32\\vssadmin.exe",
        process_guid=str(uuid.uuid4()),
        parent_process="C:\\Windows\\System32\\cmd.exe",
        command_line=random.choice(PRECURSOR_COMMANDS),
        integrity_level="System",
    )


# ---------------------------------------------------------------------
# BASELINE SCENARIOS
# ---------------------------------------------------------------------

def generate_classic_attack_session():
    """Classic sequence: driver -> privilege -> process kill -> precursor."""

    session_id = str(uuid.uuid4())
    scenario = "classic_attack"
    t0 = datetime.now(timezone.utc)

    return [
        _driver_row(
            session_id,
            scenario,
            t0,
        ),
        _priv_row(
            session_id,
            scenario,
            t0 + timedelta(seconds=8),
        ),
        _kill_row(
            session_id,
            scenario,
            t0 + timedelta(seconds=25),
        ),
        _precursor_row(
            session_id,
            scenario,
            t0 + timedelta(seconds=50),
        ),
    ]


def generate_collapsed_attack_session():
    """Collapsed attack: required burst signals occur within 5 seconds."""

    session_id = str(uuid.uuid4())
    scenario = "collapsed_attack"
    t0 = datetime.now(timezone.utc)

    return [
        _driver_row(
            session_id,
            scenario,
            t0,
        ),
        _priv_row(
            session_id,
            scenario,
            t0 + timedelta(seconds=1),
        ),
        _kill_row(
            session_id,
            scenario,
            t0 + timedelta(seconds=4),
        ),
        # Safe synthetic post-evasion activity.
        _precursor_row(
            session_id,
            scenario,
            t0 + timedelta(seconds=6),
        ),
    ]


def generate_benign_admin_session():
    """Benign administrative activity resembling individual signals."""

    session_id = str(uuid.uuid4())
    scenario = "benign_admin"
    t0 = datetime.now(timezone.utc)

    rows = [
        # Legitimate signed driver.
        _row(
            session_id,
            scenario,
            t0,
            "6",
            "benign",
            image_loaded=(
                "C:\\Windows\\System32\\drivers\\usbhub3.sys"
            ),
            hashes="SHA256=" + uuid.uuid4().hex + uuid.uuid4().hex,
            driver_signed="true",
            signer_name="Microsoft Windows",
        ),

        # Legitimate System-level command.
        _row(
            session_id,
            scenario,
            t0 + timedelta(seconds=10),
            "1",
            "benign",
            process_name="C:\\Windows\\System32\\cmd.exe",
            process_guid=str(uuid.uuid4()),
            parent_process="C:\\Windows\\explorer.exe",
            command_line="whoami /priv",
            integrity_level="System",
        ),

        # Non-security process termination.
        _row(
            session_id,
            scenario,
            t0 + timedelta(seconds=30),
            "5",
            "benign",
            process_name="WindowsUpdate.exe",
            process_guid=str(uuid.uuid4()),
        ),
    ]

    # Additional ordinary activity.
    for _ in range(2):
        rows.append(
            _row(
                session_id,
                scenario,
                t0 + timedelta(seconds=random.randint(35, 60)),
                "1",
                "benign",
                process_name=random.choice(
                    [
                        "notepad.exe",
                        "explorer.exe",
                        "chrome.exe",
                    ]
                ),
                process_guid=str(uuid.uuid4()),
                parent_process="C:\\Windows\\explorer.exe",
                command_line=random.choice(BENIGN_COMMANDS),
                integrity_level="Medium",
            )
        )

    return rows


# ---------------------------------------------------------------------
# CHALLENGE SCENARIOS
# ---------------------------------------------------------------------

def generate_benign_driver_admin_session():
    """
    Benign signed-driver activity combined with System-level administration.

    This should not be treated as a ransomware-like burst because there is
    no watched security-process termination.
    """

    session_id = str(uuid.uuid4())
    scenario = "benign_driver_admin"
    t0 = datetime.now(timezone.utc)

    return [
        # Legitimate signed driver.
        _row(
            session_id,
            scenario,
            t0,
            "6",
            "benign",
            image_loaded=(
                "C:\\Windows\\System32\\drivers\\kbdclass.sys"
            ),
            hashes="SHA256=" + uuid.uuid4().hex + uuid.uuid4().hex,
            driver_signed="true",
            signer_name="Microsoft Windows",
        ),

        # System-level administrative activity shortly after driver load.
        _row(
            session_id,
            scenario,
            t0 + timedelta(seconds=2),
            "1",
            "benign",
            process_name="C:\\Windows\\System32\\cmd.exe",
            process_guid=str(uuid.uuid4()),
            parent_process="C:\\Windows\\explorer.exe",
            command_line="whoami /priv",
            integrity_level="System",
        ),

        # Normal service-management activity, but not a watched
        # security-process termination.
        _row(
            session_id,
            scenario,
            t0 + timedelta(seconds=8),
            "1",
            "benign",
            process_name="C:\\Windows\\System32\\services.exe",
            process_guid=str(uuid.uuid4()),
            parent_process="C:\\Windows\\System32\\wininit.exe",
            command_line="services.exe",
            integrity_level="System",
        ),
    ]


def generate_partial_attack_session():
    """
    Partial attack:

        known-bad driver -> privilege escalation -> precursor

    No security-process termination occurs.
    """

    session_id = str(uuid.uuid4())
    scenario = "partial_attack"
    t0 = datetime.now(timezone.utc)

    return [
        _driver_row(
            session_id,
            scenario,
            t0,
        ),
        _priv_row(
            session_id,
            scenario,
            t0 + timedelta(seconds=2),
        ),
        _precursor_row(
            session_id,
            scenario,
            t0 + timedelta(seconds=5),
        ),
    ]


def generate_delayed_attack_session():
    """
    Delayed attack:

        driver -> privilege -> process kill -> precursor

    but the important events are spread beyond the burst window.

    This tests whether burst detection distinguishes a collapsed attack
    from a slower/staged sequence.
    """

    session_id = str(uuid.uuid4())
    scenario = "delayed_attack"
    t0 = datetime.now(timezone.utc)

    return [
        _driver_row(
            session_id,
            scenario,
            t0,
        ),
        _priv_row(
            session_id,
            scenario,
            t0 + timedelta(seconds=20),
        ),
        _kill_row(
            session_id,
            scenario,
            t0 + timedelta(seconds=45),
        ),
        _precursor_row(
            session_id,
            scenario,
            t0 + timedelta(seconds=70),
        ),
    ]


def generate_unknown_driver_attack_session():
    """
    Behavioral attack using a driver hash that is NOT in the known-bad
    reference list.

    The behavior itself remains attack-like:
        unknown driver -> privilege -> process kill -> precursor
    """

    session_id = str(uuid.uuid4())
    scenario = "unknown_driver_attack"
    t0 = datetime.now(timezone.utc)

    unknown_hash = uuid.uuid4().hex + uuid.uuid4().hex

    return [
        _row(
            session_id,
            scenario,
            t0,
            "6",
            "attack",
            image_loaded=(
                "C:\\Windows\\System32\\drivers\\sample_driver_unknown.sys"
            ),
            hashes=f"SHA256={unknown_hash}",
            driver_signed="true",
            signer_name="Unknown Test Signer",
        ),
        _priv_row(
            session_id,
            scenario,
            t0 + timedelta(seconds=1),
        ),
        _kill_row(
            session_id,
            scenario,
            t0 + timedelta(seconds=4),
        ),
        _precursor_row(
            session_id,
            scenario,
            t0 + timedelta(seconds=6),
        ),
    ]


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--sessions",
        type=int,
        default=100,
        help="number of sessions PER SCENARIO",
    )

    parser.add_argument(
        "--out",
        default="data/processed/labeled_sessions.csv",
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=42,
    )

    parser.add_argument(
        "--profile",
        choices=["baseline", "challenge"],
        default="baseline",
        help="evaluation dataset profile",
    )

    args = parser.parse_args()

    random.seed(args.seed)

    all_rows = []

    # -------------------------------------------------------------
    # Baseline scenarios are always included.
    # -------------------------------------------------------------

    for _ in range(args.sessions):

        all_rows.extend(
            generate_classic_attack_session()
        )

        all_rows.extend(
            generate_collapsed_attack_session()
        )

        all_rows.extend(
            generate_benign_admin_session()
        )

        # ---------------------------------------------------------
        # Additional challenge scenarios.
        # ---------------------------------------------------------

        if args.profile == "challenge":

            all_rows.extend(
                generate_benign_driver_admin_session()
            )

            all_rows.extend(
                generate_partial_attack_session()
            )

            all_rows.extend(
                generate_delayed_attack_session()
            )

            all_rows.extend(
                generate_unknown_driver_attack_session()
            )

    # Shuffle rows while keeping each session's session_id intact.
    random.shuffle(all_rows)

    # -------------------------------------------------------------
    # Write CSV.
    # -------------------------------------------------------------

    with open(
        args.out,
        "w",
        newline="",
        encoding="utf-8",
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=FIELDNAMES,
        )

        writer.writeheader()
        writer.writerows(all_rows)

    # -------------------------------------------------------------
    # Dataset statistics.
    # -------------------------------------------------------------

    if args.profile == "baseline":
        scenario_count = 3
    else:
        scenario_count = 7

    sessions = args.sessions * scenario_count

    attacks = sum(
        1
        for row in all_rows
        if row["label"] == "attack"
    )

    benign = len(all_rows) - attacks

    print(
        f"Wrote {len(all_rows)} rows "
        f"({sessions} sessions) to {args.out}"
    )

    print(
        f"Profile: {args.profile}"
    )

    if args.profile == "baseline":

        print(
            "Scenarios: "
            f"classic_attack={args.sessions}, "
            f"collapsed_attack={args.sessions}, "
            f"benign_admin={args.sessions}"
        )

    else:

        print(
            "Scenarios: "
            f"classic_attack={args.sessions}, "
            f"collapsed_attack={args.sessions}, "
            f"benign_admin={args.sessions}, "
            f"benign_driver_admin={args.sessions}, "
            f"partial_attack={args.sessions}, "
            f"delayed_attack={args.sessions}, "
            f"unknown_driver_attack={args.sessions}"
        )

    print(
        f"Row label split: "
        f"attack={attacks}, "
        f"benign={benign}"
    )


if __name__ == "__main__":
    main()