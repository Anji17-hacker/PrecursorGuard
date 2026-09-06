import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agent.session_tracker import HostStateTracker
from agent.event_source import SimulatedLiveEventSource, KNOWN_BAD_HASH

KNOWN_BAD = {KNOWN_BAD_HASH}


def test_attack_scenario_fires_new_alert_before_full_sequence_completes():
    tracker = HostStateTracker(known_bad_hashes=KNOWN_BAD)
    source = SimulatedLiveEventSource(scenario="attack", speed=0)  # no real delay in tests

    events = list(source.stream())
    assert len(events) == 4  # driver-load, process-create, process-terminate, precursor-command

    new_alert_indices = []
    for i, event in enumerate(events):
        result = tracker.ingest(event)
        if result["new_alert"]:
            new_alert_indices.append(i)

    assert len(new_alert_indices) == 1, "should alert exactly once, not once per event"
    # The alert should fire on event index 1 (privilege escalation, right after the
    # driver load) — BEFORE the security-process-kill (index 2) or the precursor
    # command (index 3). This is the actual claim: detection before the attack
    # sequence finishes, not after a batch export.
    assert new_alert_indices[0] < 2


def test_benign_scenario_never_alerts():
    tracker = HostStateTracker(known_bad_hashes=KNOWN_BAD)
    source = SimulatedLiveEventSource(scenario="benign", speed=0)

    for event in source.stream():
        result = tracker.ingest(event)
        assert result["alert"] is False
        assert result["risk_score"] == 0.0
