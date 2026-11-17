from datetime import datetime, timedelta, timezone

import pytest

import src.pipeline as pipeline_module
from src.pipeline import build_events_query, parse_since, run_pipeline

T0 = datetime(2026, 11, 8, 10, 0, 0, tzinfo=timezone.utc)


def failed(i):
    return {
        "event_id": f"e{i}", "source": "cowrie", "event_type": "cowrie.login.failed",
        "session_id": "s1", "src_ip": "172.17.0.1",
        "event_timestamp": T0 + timedelta(seconds=i * 5),
    }


def test_run_pipeline_builds_an_incident_from_one_session():
    detections, incidents = run_pipeline([failed(i) for i in range(5)])
    assert detections
    assert len(incidents) == 1
    assert incidents[0].session_id == "s1"


def test_run_pipeline_is_idempotent_on_ids():
    now = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)
    events = [failed(i) for i in range(5)]
    a = run_pipeline(events, now)
    b = run_pipeline(events, now)
    assert [d.detection_id for d in a[0]] == [d.detection_id for d in b[0]]
    assert [i.incident_id for i in a[1]] == [i.incident_id for i in b[1]]


def test_parse_since_accepts_z_and_rejects_naive():
    assert parse_since("2026-11-19T00:00:00Z").tzinfo is not None
    with pytest.raises(ValueError):
        parse_since("2026-11-19T00:00:00")


def test_query_without_since_has_no_filter():
    query, params = build_events_query(None)
    assert "WHERE" not in query and params == {}


def test_query_with_since_loads_whole_sessions_and_binds_the_date():
    since = parse_since("2026-11-19T00:00:00Z")
    query, params = build_events_query(since)
    assert "(source, session_id) IN" in query
    assert params == {"since": since}
    assert "2026-11-19" not in query


def test_query_never_selects_message_or_raw_event():
    query, _ = build_events_query(None)
    assert "raw_event" not in query and "message" not in query


class _Conn:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_dry_run_reads_but_never_writes(monkeypatch):
    monkeypatch.setattr(pipeline_module, "load_dotenv", lambda *a, **k: None)
    monkeypatch.setenv("DATABASE_URL", "postgresql://x@127.0.0.1/db")
    monkeypatch.setattr(pipeline_module.psycopg, "connect", lambda *a, **k: _Conn())
    monkeypatch.setattr(pipeline_module, "fetch_events",
                        lambda conn, since: [failed(i) for i in range(5)])
    written = []
    monkeypatch.setattr(pipeline_module, "write_results",
                        lambda *a, **k: written.append(1))
    assert pipeline_module.main(["--dry-run"]) == 0
    assert written == []


def test_missing_database_url_returns_error(monkeypatch):
    monkeypatch.setattr(pipeline_module, "load_dotenv", lambda *a, **k: None)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert pipeline_module.main([]) == 2