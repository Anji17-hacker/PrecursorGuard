import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detection.rule_detector import extract_sha256
from detection.precursor_detector import matches_precursor_pattern


def test_extract_sha256_from_sysmon_hashes_field():
    field = "SHA1=abc,MD5=def,SHA256=3b1e9a2c1f6d4e8a9c0b7f2d5e6a1c3b4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a,IMPHASH=ghi"
    assert extract_sha256(field) == "3b1e9a2c1f6d4e8a9c0b7f2d5e6a1c3b4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a"


def test_extract_sha256_returns_none_when_absent():
    assert extract_sha256("SHA1=abc,MD5=def") is None
    assert extract_sha256(None) is None
    assert extract_sha256("") is None


def test_precursor_pattern_matches_vssadmin():
    assert matches_precursor_pattern("vssadmin.exe delete shadows /all /quiet") is True


def test_precursor_pattern_matches_service_stop():
    assert matches_precursor_pattern("net.exe stop SentinelAgent") is True
    assert matches_precursor_pattern("sc.exe stop MsMpEng") is True


def test_precursor_pattern_ignores_benign_commands():
    assert matches_precursor_pattern("notepad.exe C:\\Users\\demo\\notes.txt") is False
    assert matches_precursor_pattern("chrome.exe --new-window") is False
    assert matches_precursor_pattern(None) is False
    assert matches_precursor_pattern("") is False
