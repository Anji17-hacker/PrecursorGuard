#!/usr/bin/env python3
"""
rule_detector.py

Phase 5 of the roadmap: the first, simplest detector. Loads the
LOLDrivers reference list and flags any Sysmon Event ID 6 (driver
loaded) row whose hash matches a known-vulnerable/malicious driver.

This module is imported by pipeline.py; it can also run standalone:

    python rule_detector.py data/processed/labeled_sessions.csv data/loldrivers_reference.csv
"""
import sys
import re
import pandas as pd


def load_reference(path):
    ref = pd.read_csv(path)
    return set(ref["sha256"].str.lower().str.strip())


def extract_sha256(hashes_field):
    """Sysmon's Hashes field looks like: 'SHA1=...,MD5=...,SHA256=...,IMPHASH=...'"""
    if not isinstance(hashes_field, str):
        return None
    match = re.search(r"SHA256=([0-9A-Fa-f]{64})", hashes_field)
    return match.group(1).lower() if match else None


def flag_driver_loads(df, known_bad_hashes):
    """Returns df filtered to Event ID 6 rows, with a rule_match boolean column added."""
    driver_loads = df[df["event_id"] == 6].copy()
    driver_loads["sha256"] = driver_loads["hashes"].apply(extract_sha256)
    driver_loads["rule_match"] = driver_loads["sha256"].isin(known_bad_hashes)
    return driver_loads


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)

    sessions_path, reference_path = sys.argv[1], sys.argv[2]
    df = pd.read_csv(sessions_path)
    df["event_id"] = df["event_id"].astype(int)

    known_bad = load_reference(reference_path)
    driver_loads = flag_driver_loads(df, known_bad)

    matches = driver_loads[driver_loads["rule_match"]]
    print(f"Scanned {len(driver_loads)} driver-load events across the dataset.")
    print(f"Found {len(matches)} matches against {len(known_bad)} known-bad hashes.")
    if len(matches):
        print(matches[["session_id", "timestamp", "image_loaded"]].to_string(index=False))


if __name__ == "__main__":
    main()
