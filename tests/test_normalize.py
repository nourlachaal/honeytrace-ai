
from datetime import timezone

from src.normalization.normalize import normalize_event


def test_normalize_cowrie_event_redacts_password():
    raw = {
        "eventid": "cowrie.login.success",
        "timestamp": "2026-10-27T23:32:38.168799Z",
        "session": "example-session",
        "protocol": "ssh",
        "src_ip": "127.0.0.1",
        "username": "testuser",
        "password": "example-secret",
        "message": "Test event",
    }

    result = normalize_event(raw)

    assert result["source"] == "cowrie"
    assert result["event_type"] == "cowrie.login.success"
    assert result["session_id"] == "example-session"
    assert result["event_timestamp"].tzinfo is not None
    assert result["event_timestamp"].utcoffset().total_seconds() == 0
    assert result["raw_event"]["password"] == "[REDACTED]"
    assert "example-secret" not in str(result)
    assert len(result["event_id"]) == 64


def test_same_event_has_same_id():
    raw = {
        "eventid": "cowrie.session.connect",
        "timestamp": "2026-10-27T23:31:36.607236Z",
        "session": "example-session",
    }

    first = normalize_event(raw)
    second = normalize_event(raw)

    assert first["event_id"] == second["event_id"]


def test_timezone_is_normalized_to_utc():
    raw = {
        "eventid": "cowrie.session.connect",
        "timestamp": "2026-10-28T01:00:00+01:00",
    }

    result = normalize_event(raw)

    assert result["event_timestamp"].hour == 0
    assert result["event_timestamp"].day == 28
    assert result["event_timestamp"].tzinfo == timezone.utc
import pytest


def test_missing_timestamp_is_rejected():
    raw = {
        "eventid": "cowrie.session.connect",
        "session": "example-session",
    }

    with pytest.raises(ValueError, match="timestamp"):
        normalize_event(raw)


def test_unsupported_source_is_rejected():
    raw = {
        "eventid": "test.event",
        "timestamp": "2026-10-28T10:00:00Z",
    }

    with pytest.raises(ValueError, match="Unsupported event source"):
        normalize_event(raw, source="unknown")


def test_nested_sensitive_fields_are_redacted():
    raw = {
        "eventid": "cowrie.test",
        "timestamp": "2026-10-28T10:00:00Z",
        "metadata": {
            "password": "example-secret",
            "nested": {"token": "example-token"},
        },
    }

    result = normalize_event(raw)

    assert result["raw_event"]["metadata"]["password"] == "[REDACTED]"
    assert result["raw_event"]["metadata"]["nested"]["token"] == "[REDACTED]"
    assert "example-secret" not in str(result)
    assert "example-token" not in str(result)