#!/usr/bin/env python3
"""
agent/live_watcher.py

Real-time PrecursorGuard event watcher.

Two modes:

  Offline demo:
    python agent/live_watcher.py --mode simulated --scenario attack

  Real Windows endpoint:
    python agent/live_watcher.py --mode windows

The watcher connects:

    Event Source
         |
         v
    HostStateTracker
         |
         v
    Risk Scoring
         |
         v
    Alert

Important:
    Event ID 10 (ProcessAccess) is still sent to the tracker because
    behavioral correlation may use it internally.

    However, ProcessAccess events can occur extremely frequently on a
    normal Windows system. Therefore they are not printed individually
    to the console.

This keeps the live console readable without removing telemetry from
the detection pipeline.
"""

import argparse
import os
import sys


# ---------------------------------------------------------------------
# Project root
# ---------------------------------------------------------------------

sys.path.insert(
    0,
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)


# ---------------------------------------------------------------------
# Project imports
# ---------------------------------------------------------------------

from agent.session_tracker import HostStateTracker
from agent.event_source import (
    SimulatedLiveEventSource,
    WindowsLiveEventSource,
)

from detection.rule_detector import load_reference

from response.alerts import (
    log_alert,
    format_alert_console,
)

from config.settings import LOLDRIVERS_REFERENCE_PATH


# ---------------------------------------------------------------------
# Event labels
# ---------------------------------------------------------------------

EVENT_LABELS = {
    "1": "process-create",
    "5": "process-terminate",
    "6": "driver-load",
    "10": "process-access",
}


# ---------------------------------------------------------------------
# Console display policy
# ---------------------------------------------------------------------

# These events are important enough to display individually.
#
# Event ID 10 is deliberately excluded from this list because it can
# generate a very large amount of normal Windows telemetry.
#
# IMPORTANT:
# Event ID 10 is NOT ignored by the detector.
# It is still passed into tracker.ingest().
DISPLAY_EVENT_IDS = {
    "1",
    "5",
    "6",
}


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def main():

    parser = argparse.ArgumentParser(
        description="PrecursorGuard real-time detection watcher"
    )

    parser.add_argument(
        "--mode",
        choices=["simulated", "windows"],
        default="simulated",
        help="Event source mode"
    )

    parser.add_argument(
        "--scenario",
        choices=["attack", "benign"],
        default="attack",
        help="Scenario used only in simulated mode"
    )

    parser.add_argument(
        "--reference",
        default=LOLDRIVERS_REFERENCE_PATH,
        help="Path to LOLDrivers reference CSV"
    )

    parser.add_argument(
        "--speed",
        type=float,
        default=0.15,
        help=(
            "Seconds of real delay per simulated second "
            "(simulated mode only)"
        )
    )

    args = parser.parse_args()


    # -----------------------------------------------------------------
    # Load known-bad driver reference
    # -----------------------------------------------------------------

    known_bad = load_reference(args.reference)


    # -----------------------------------------------------------------
    # Initialize behavioral tracker
    # -----------------------------------------------------------------

    tracker = HostStateTracker(
        known_bad_hashes=known_bad
    )


    # -----------------------------------------------------------------
    # Select event source
    # -----------------------------------------------------------------

    if args.mode == "simulated":

        source = SimulatedLiveEventSource(
            scenario=args.scenario,
            speed=args.speed
        )

    else:

        source = WindowsLiveEventSource()


    # -----------------------------------------------------------------
    # Startup message
    # -----------------------------------------------------------------

    print(
        f"[PrecursorGuard live watcher] "
        f"mode={args.mode} — watching for "
        f"driver-load -> privilege-escalation -> "
        f"EDR-kill -> precursor-command sequences...\n"
    )


    # -----------------------------------------------------------------
    # Live event loop
    # -----------------------------------------------------------------

    try:

        for event in source.stream():

            # ---------------------------------------------------------
            # IMPORTANT:
            # Every event is still passed to the tracker.
            #
            # This means Event ID 10 ProcessAccess is NOT discarded.
            # ---------------------------------------------------------

            result = tracker.ingest(event)


            # ---------------------------------------------------------
            # Extract event information
            # ---------------------------------------------------------

            eid = str(event.get("event_id", ""))

            label = EVENT_LABELS.get(
                eid,
                eid
            )


            # ---------------------------------------------------------
            # Console output
            #
            # Only display important events individually.
            # Event ID 10 is intentionally suppressed here because
            # normal Windows systems generate many ProcessAccess events.
            # ---------------------------------------------------------

            if eid in DISPLAY_EVENT_IDS:

                print(
                    f"[{result['timestamp']}] "
                    f"event={label:18s} "
                    f"risk_score={result['risk_score']:.3f}"
                )


            # ---------------------------------------------------------
            # ALERT HANDLING
            #
            # Alerts are ALWAYS displayed, regardless of event ID.
            #
            # Therefore, if a ProcessAccess event contributes to a
            # score crossing the threshold, we will still see the alert.
            # ---------------------------------------------------------

            if result["new_alert"]:

                print(
                    "\n"
                    + format_alert_console(result)
                    + "\n"
                )

                log_alert(result)


    except KeyboardInterrupt:

        print(
            "\n[PrecursorGuard] Watcher stopped by user."
        )


    # -----------------------------------------------------------------
    # Stream ended
    # -----------------------------------------------------------------

    print("\nStream ended.")


# ---------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------

if __name__ == "__main__":
    main()