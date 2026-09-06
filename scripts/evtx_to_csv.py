#!/usr/bin/env python3
"""
evtx_to_csv.py

Converts an exported Sysmon .evtx file into the fixed CSV schema used
by every downstream component of PrecursorGuard.

Requires: pip install python-evtx pandas

Usage:
    python evtx_to_csv.py sysmon_export.evtx data/raw/session_001.csv

Output CSV schema (fixed — do not change without updating every
downstream script):
    timestamp, event_id, process_name, process_guid, parent_process,
    image_loaded, driver_signed, signer_name, target_process,
    command_line, hashes, integrity_level
"""
import sys
import csv
from xml.etree import ElementTree as ET

try:
    from Evtx.Evtx import Evtx
except ImportError:
    print("Missing dependency. Run: pip install python-evtx --break-system-packages")
    sys.exit(1)

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

FIELDNAMES = [
    "timestamp", "event_id", "process_name", "process_guid",
    "parent_process", "image_loaded", "driver_signed", "signer_name",
    "target_process", "command_line", "hashes", "integrity_level",
]


def _data(event_data_elem, name):
    if event_data_elem is None:
        return ""
    for d in event_data_elem.findall("e:Data", NS):
        if d.get("Name") == name:
            return (d.text or "").strip()
    return ""


def parse_record(xml_str):
    root = ET.fromstring(xml_str)
    system = root.find("e:System", NS)
    event_data = root.find("e:EventData", NS)

    event_id = system.find("e:EventID", NS).text
    time_created = system.find("e:TimeCreated", NS)
    timestamp = time_created.get("SystemTime") if time_created is not None else ""

    row = {fn: "" for fn in FIELDNAMES}
    row["timestamp"] = timestamp
    row["event_id"] = event_id

    if event_id == "1":  # Process creation
        row["process_name"] = _data(event_data, "Image")
        row["process_guid"] = _data(event_data, "ProcessGuid")
        row["parent_process"] = _data(event_data, "ParentImage")
        row["command_line"] = _data(event_data, "CommandLine")
        row["hashes"] = _data(event_data, "Hashes")
        row["integrity_level"] = _data(event_data, "IntegrityLevel")
    elif event_id == "5":  # Process termination
        row["process_name"] = _data(event_data, "Image")
        row["process_guid"] = _data(event_data, "ProcessGuid")
    elif event_id == "6":  # Driver loaded
        row["image_loaded"] = _data(event_data, "ImageLoaded")
        row["hashes"] = _data(event_data, "Hashes")
        row["driver_signed"] = _data(event_data, "Signed")
        row["signer_name"] = _data(event_data, "Signature")
    elif event_id == "10":  # Process access
        row["process_name"] = _data(event_data, "SourceImage")
        row["target_process"] = _data(event_data, "TargetImage")

    return row


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)

    evtx_path, csv_path = sys.argv[1], sys.argv[2]
    rows = []
    skipped = 0

    with Evtx(evtx_path) as log:
        for record in log.records():
            try:
                rows.append(parse_record(record.xml()))
            except Exception:
                skipped += 1
                continue

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to {csv_path} ({skipped} unparseable records skipped)")


if __name__ == "__main__":
    main()
