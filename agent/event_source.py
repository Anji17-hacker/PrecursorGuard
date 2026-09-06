#!/usr/bin/env python3
"""
agent/event_source.py

PrecursorGuard live event sources.

Two sources:

1. SimulatedLiveEventSource
   - Offline demonstration/testing.
   - Generates a realistic precursor sequence.

2. WindowsLiveEventSource
   - Reads Microsoft-Windows-Sysmon/Operational in real time.
   - Starts after the newest existing EventRecordID.
   - Processes newly arriving Sysmon events.
   - Supports:
       Event ID 1  - Process Create
       Event ID 5  - Process Terminate
       Event ID 6  - Driver Load
       Event ID 10 - Process Access
       Event ID 11 - File Create
       Event ID 13 - Registry Value Set
"""

import time
from datetime import datetime, timezone
from xml.etree import ElementTree as ET


# ---------------------------------------------------------------------
# Reference test hash
# ---------------------------------------------------------------------

KNOWN_BAD_HASH = (
    "3b1e9a2c1f6d4e8a9c0b7f2d5e6a1c3b4"
    "d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a"
)


# ---------------------------------------------------------------------
# Simulated live source
# ---------------------------------------------------------------------

class SimulatedLiveEventSource:
    """
    Generates events one at a time with real delays.

    Used for offline testing of the complete PrecursorGuard pipeline.
    """

    def __init__(self, scenario="attack", speed=0.15):
        self.scenario = scenario
        self.speed = speed

    def _emit(self, event_id, delay_after, **fields):
        row = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_id": str(event_id),

            "process_name": "",
            "process_guid": "",
            "parent_process": "",

            "image_loaded": "",
            "driver_signed": "",
            "signer_name": "",

            "target_process": "",
            "command_line": "",
            "hashes": "",
            "integrity_level": "",

            "target_filename": "",
            "registry_key": "",
            "registry_value": "",
        }

        row.update(fields)

        time.sleep(delay_after * self.speed)

        return row

    def stream(self):

        if self.scenario == "benign":

            yield self._emit(
                "1",
                1,
                process_name=r"C:\Windows\System32\notepad.exe",
                process_guid="{BENIGN-001}",
                parent_process=r"C:\Windows\explorer.exe",
                command_line="notepad.exe",
                integrity_level="Medium",
            )

            yield self._emit(
                "1",
                2,
                process_name=r"C:\Windows\System32\cmd.exe",
                process_guid="{BENIGN-002}",
                parent_process=r"C:\Windows\explorer.exe",
                command_line="cmd.exe /c whoami",
                integrity_level="Medium",
            )

            yield self._emit(
                "5",
                2,
                process_name=r"C:\Windows\System32\notepad.exe",
                process_guid="{BENIGN-001}",
            )

            return

        # -------------------------------------------------------------
        # Simulated attack sequence
        # -------------------------------------------------------------

        yield self._emit(
            "6",
            1,
            image_loaded=r"C:\Windows\System32\drivers\evil.sys",
            hashes="SHA256=" + KNOWN_BAD_HASH,
            driver_signed="false",
            signer_name="Unknown",
        )

        yield self._emit(
            "1",
            1,
            process_name=r"C:\Windows\System32\cmd.exe",
            process_guid="{ATTACK-001}",
            parent_process=r"C:\Windows\explorer.exe",
            command_line="cmd.exe /c whoami /priv",
            integrity_level="System",
        )

        yield self._emit(
            "5",
            2,
            process_name=r"C:\Program Files\FakeEDR\fake_edr.exe",
            process_guid="{FAKE-EDR-001}",
        )

        yield self._emit(
            "1",
            3,
            process_name=r"C:\Windows\System32\vssadmin.exe",
            process_guid="{ATTACK-002}",
            parent_process=r"C:\Windows\System32\cmd.exe",
            command_line="vssadmin.exe delete shadows /all /quiet",
            integrity_level="System",
        )


# ---------------------------------------------------------------------
# Real Windows Sysmon source
# ---------------------------------------------------------------------

class WindowsLiveEventSource:
    """
    Real-time Sysmon event source.

    Reads:

        Microsoft-Windows-Sysmon/Operational

    Important behavior:

    - Does NOT replay the existing Sysmon backlog.
    - Finds the current newest EventRecordID.
    - Then watches only records arriving after that ID.
    - Uses the Windows Event Log API through pywin32.
    """

    CHANNEL = "Microsoft-Windows-Sysmon/Operational"

    NS = {
        "e": "http://schemas.microsoft.com/win/2004/08/events/event"
    }

    def __init__(self, poll_interval=1.0):
        self.poll_interval = poll_interval

    # -----------------------------------------------------------------
    # XML helper
    # -----------------------------------------------------------------

    @staticmethod
    def _find_data(event_data, name):
        """
        Extract a named <Data Name="..."> field from Sysmon XML.
        """

        if event_data is None:
            return ""

        for node in event_data.findall("e:Data", WindowsLiveEventSource.NS):
            if node.get("Name") == name:
                return (node.text or "").strip()

        return ""

    # -----------------------------------------------------------------
    # Parse one Sysmon XML event
    # -----------------------------------------------------------------

    def _parse(self, xml_str):

        root = ET.fromstring(xml_str)

        system = root.find("e:System", self.NS)
        event_data = root.find("e:EventData", self.NS)

        if system is None:
            raise ValueError("Sysmon event has no System section")

        event_id_node = system.find("e:EventID", self.NS)

        if event_id_node is None:
            raise ValueError("Sysmon event has no EventID")

        event_id = str(event_id_node.text or "").strip()

        # -------------------------------------------------------------
        # Timestamp
        # -------------------------------------------------------------

        time_created = system.find("e:TimeCreated", self.NS)

        if time_created is not None:
            timestamp = time_created.get("SystemTime")
        else:
            timestamp = datetime.now(timezone.utc).isoformat()

        # -------------------------------------------------------------
        # EventRecordID
        # -------------------------------------------------------------

        record_node = system.find("e:EventRecordID", self.NS)

        record_id = None

        if record_node is not None and record_node.text:
            try:
                record_id = int(record_node.text)
            except ValueError:
                record_id = None

        # -------------------------------------------------------------
        # Common fields
        # -------------------------------------------------------------

        row = {
            "timestamp": timestamp,
            "event_id": event_id,
            "record_id": record_id,

            "process_name": "",
            "process_guid": "",
            "parent_process": "",

            "image_loaded": "",
            "driver_signed": "",
            "signer_name": "",

            "target_process": "",
            "command_line": "",
            "hashes": "",
            "integrity_level": "",

            "target_filename": "",

            "registry_key": "",
            "registry_value": "",
        }

        # -------------------------------------------------------------
        # Event ID 1 - Process Create
        # -------------------------------------------------------------

        if event_id == "1":

            row.update(
                process_name=self._find_data(event_data, "Image"),
                process_guid=self._find_data(event_data, "ProcessGuid"),
                parent_process=self._find_data(event_data, "ParentImage"),
                command_line=self._find_data(event_data, "CommandLine"),
                hashes=self._find_data(event_data, "Hashes"),
                integrity_level=self._find_data(
                    event_data,
                    "IntegrityLevel"
                ),
            )

        # -------------------------------------------------------------
        # Event ID 5 - Process Terminate
        # -------------------------------------------------------------

        elif event_id == "5":

            row.update(
                process_name=self._find_data(event_data, "Image"),
                process_guid=self._find_data(event_data, "ProcessGuid"),
            )

        # -------------------------------------------------------------
        # Event ID 6 - Driver Load
        # -------------------------------------------------------------

        elif event_id == "6":

            row.update(
                image_loaded=self._find_data(
                    event_data,
                    "ImageLoaded"
                ),
                hashes=self._find_data(
                    event_data,
                    "Hashes"
                ),
                driver_signed=self._find_data(
                    event_data,
                    "Signed"
                ),
                signer_name=self._find_data(
                    event_data,
                    "Signature"
                ),
            )

        # -------------------------------------------------------------
        # Event ID 10 - Process Access
        # -------------------------------------------------------------

        elif event_id == "10":

            row.update(
                process_name=self._find_data(
                    event_data,
                    "SourceImage"
                ),
                target_process=self._find_data(
                    event_data,
                    "TargetImage"
                ),
            )

        # -------------------------------------------------------------
        # Event ID 11 - File Create
        #
        # This is important for ransomware behavior testing.
        # -------------------------------------------------------------

        elif event_id == "11":

            row.update(
                process_name=self._find_data(
                    event_data,
                    "Image"
                ),
                process_guid=self._find_data(
                    event_data,
                    "ProcessGuid"
                ),
                target_filename=self._find_data(
                    event_data,
                    "TargetFilename"
                ),
            )

        # -------------------------------------------------------------
        # Event ID 13 - Registry Value Set
        # -------------------------------------------------------------

        elif event_id == "13":

            row.update(
                process_name=self._find_data(
                    event_data,
                    "Image"
                ),
                process_guid=self._find_data(
                    event_data,
                    "ProcessGuid"
                ),
                registry_key=self._find_data(
                    event_data,
                    "TargetObject"
                ),
                registry_value=self._find_data(
                    event_data,
                    "Details"
                ),
            )

        return row

    # -----------------------------------------------------------------
    # Find latest existing EventRecordID
    # -----------------------------------------------------------------

    def _get_latest_record_id(self, win32evtlog):

        query = win32evtlog.EvtQuery(
            self.CHANNEL,
            win32evtlog.EvtQueryChannelPath
            | win32evtlog.EvtQueryReverseDirection,
        )

        events = win32evtlog.EvtNext(
            query,
            1,
            Timeout=3000,
        )

        if not events:
            return 0

        xml_str = win32evtlog.EvtRender(
            events[0],
            win32evtlog.EvtRenderEventXml,
        )

        root = ET.fromstring(xml_str)

        system = root.find("e:System", self.NS)

        if system is None:
            return 0

        record_node = system.find(
            "e:EventRecordID",
            self.NS,
        )

        if record_node is None:
            return 0

        try:
            return int(record_node.text)
        except (TypeError, ValueError):
            return 0

    # -----------------------------------------------------------------
    # Live stream
    # -----------------------------------------------------------------

    def stream(self):

        import win32evtlog

        # -------------------------------------------------------------
        # Determine current newest record.
        # -------------------------------------------------------------

        last_record_id = self._get_latest_record_id(
            win32evtlog
        )

        print(
            f"[WindowsLiveEventSource] "
            f"Starting after EventRecordID={last_record_id}"
        )

        # -------------------------------------------------------------
        # Continuously create a query for records newer than the
        # last event we processed.
        #
        # This intentionally avoids relying on an old query cursor.
        # -------------------------------------------------------------

        while True:

            xpath = (
                "*[System["
                f"EventRecordID > {last_record_id}"
                "]]"
            )

            try:

                query = win32evtlog.EvtQuery(
                    self.CHANNEL,
                    win32evtlog.EvtQueryChannelPath,
                    xpath,
                )

                events = win32evtlog.EvtNext(
                    query,
                    50,
                    Timeout=1000,
                )

            except Exception as exc:

                print(
                    f"[WindowsLiveEventSource] "
                    f"Event query error: {exc}"
                )

                time.sleep(self.poll_interval)

                continue

            # ---------------------------------------------------------
            # Nothing new yet.
            # ---------------------------------------------------------

            if not events:

                time.sleep(self.poll_interval)

                continue

            # ---------------------------------------------------------
            # EvtQuery returns chronological events for this query.
            # Process them in the order returned.
            # ---------------------------------------------------------

            for event_handle in events:

                try:

                    xml_str = win32evtlog.EvtRender(
                        event_handle,
                        win32evtlog.EvtRenderEventXml,
                    )

                    event = self._parse(xml_str)

                    record_id = event.get("record_id")

                    if (
                        record_id is not None
                        and record_id <= last_record_id
                    ):
                        continue

                    if record_id is not None:
                        last_record_id = record_id

                    # -------------------------------------------------
                    # Debug line specifically useful during testing.
                    # -------------------------------------------------

                    if event["event_id"] == "11":

                        print(
                            "[WindowsLiveEventSource] "
                            f"Event 11 FileCreate: "
                            f"{event.get('target_filename', '')}"
                        )

                    elif event["event_id"] == "6":

                        print(
                            "[WindowsLiveEventSource] "
                            f"Event 6 DriverLoad: "
                            f"{event.get('image_loaded', '')}"
                        )

                    yield event

                except Exception as exc:

                    print(
                        "[WindowsLiveEventSource] "
                        f"Parse error: {exc}"
                    )

            time.sleep(0.05)
