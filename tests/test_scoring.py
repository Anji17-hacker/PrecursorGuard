import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scoring.risk_score import compute_risk_score, is_alert, normalize_precursor_count
from config.settings import RISK_WEIGHTS, ALERT_THRESHOLD


def test_weights_sum_to_one():
    assert abs(sum(RISK_WEIGHTS.values()) - 1.0) < 1e-9


def test_no_signals_gives_zero_risk():
    score, sub = compute_risk_score(False, False, False, 0)
    assert score == 0.0
    assert is_alert(score) is False


def test_all_signals_gives_max_risk():
    score, sub = compute_risk_score(True, True, True, 5)
    assert score == 1.0
    assert is_alert(score) is True


def test_driver_reputation_alone_is_below_threshold():
    """A single hash match with no behavioral corroboration should not
    alone cross the alert threshold — that's the whole point of the
    hybrid design (rule match alone isn't enough)."""
    score, sub = compute_risk_score(True, False, False, 0)
    assert score == RISK_WEIGHTS["driver_reputation"]
    assert score < ALERT_THRESHOLD


def test_driver_plus_privilege_escalation_crosses_threshold():
    score, sub = compute_risk_score(True, True, False, 0)
    assert score >= ALERT_THRESHOLD
    assert is_alert(score) is True


def test_precursor_count_normalizes_and_caps():
    assert normalize_precursor_count(0) == 0.0
    assert normalize_precursor_count(3) == 1.0
    assert normalize_precursor_count(10) == 1.0  # caps at 1.0, doesn't exceed


def test_burst_score_requires_privilege_escalation_and_kill():
    from scoring.risk_score import compute_burst_score
    assert compute_burst_score(True, True, False, 4) == 0.0
    assert compute_burst_score(True, False, True, 4) == 0.0


def test_burst_score_fires_inside_window():
    from scoring.risk_score import compute_burst_score
    assert compute_burst_score(True, True, True, 5) == 1.0


def test_burst_score_does_not_fire_outside_window():
    from scoring.risk_score import compute_burst_score
    assert compute_burst_score(True, True, True, 5.1) == 0.0


def test_burst_score_fires_without_known_driver_hash():
    """Regression test: an unrecognized/zero-day driver must not defeat
    burst detection. Privilege escalation + security-process kill inside
    the burst window is itself the precursor signal — a LOLDrivers hash
    match is corroborating evidence, not a prerequisite."""
    from scoring.risk_score import compute_burst_score
    assert compute_burst_score(False, True, True, 4) == 1.0


def test_two_of_three_primary_signals_crosses_threshold():
    """Any two of {driver reputation, privilege escalation, process kill}
    together should reach ALERT_THRESHOLD (0.30 + 0.30 = 0.60), including
    combinations that don't involve a driver hash match at all — this is
    what lets a partial/zero-day BYOVD attack still raise an alert."""
    score, _ = compute_risk_score(False, True, True, 0)
    assert score >= ALERT_THRESHOLD
    assert is_alert(score) is True
