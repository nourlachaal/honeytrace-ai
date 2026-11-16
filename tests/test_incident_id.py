import hashlib
import re

from src.correlation.correlator import _incident_id


def test_incident_id_is_the_documented_byte_string():
    expected = hashlib.sha256("incident|cowrie|abc123".encode("utf-8")).hexdigest()
    assert _incident_id("cowrie", "abc123") == expected


def test_incident_id_is_64_lowercase_hex():
    assert re.fullmatch(r"[0-9a-f]{64}", _incident_id("cowrie", "abc123"))


def test_incident_id_is_case_and_space_sensitive():
    base = _incident_id("cowrie", "abc")
    assert _incident_id("cowrie", "ABC") != base
    assert _incident_id("cowrie", "abc ") != base


def test_incident_id_depends_on_source():
    assert _incident_id("cowrie", "s1") != _incident_id("juice_shop", "s1")