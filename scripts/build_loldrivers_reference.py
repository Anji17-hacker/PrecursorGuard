#!/usr/bin/env python3
"""
build_loldrivers_reference.py

Normalizes a full LOLDrivers.io export (JSON) into the flat CSV schema
used by detection/rule_detector.py:

    driver_name, sha256, category, verified_vulnerable

Usage:
    python build_loldrivers_reference.py loldrivers_full.json data/loldrivers_reference.csv
"""
import sys
import json
import csv


def normalize(raw_entries):
    rows = []
    for entry in raw_entries:
        name = entry.get("Filename") or entry.get("filename") or entry.get("name")
        category = (entry.get("Category") or entry.get("category") or "vulnerable").lower()
        known_vulnerable = entry.get("KnownVulnerableSamples") or entry.get("Samples") or []
        if not known_vulnerable:
            continue
        for sample in known_vulnerable:
            sha256 = sample.get("SHA256") or sample.get("sha256")
            if not sha256 or not name:
                continue
            rows.append({
                "driver_name": name,
                "sha256": sha256.lower(),
                "category": category,
                "verified_vulnerable": "true",
            })
    return rows


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)

    src_path, dst_path = sys.argv[1], sys.argv[2]

    with open(src_path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    rows = normalize(raw if isinstance(raw, list) else raw.get("drivers", []))

    if not rows:
        print("No rows extracted — check the source JSON's field names "
              "(LOLDrivers has changed its export shape before).")
        sys.exit(1)

    with open(dst_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["driver_name", "sha256", "category", "verified_vulnerable"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} driver hash rows to {dst_path}")


if __name__ == "__main__":
    main()
