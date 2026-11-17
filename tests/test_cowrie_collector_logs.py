import json

from src.collectors.cowrie_collector import (
    find_log_files,
    read_cowrie_events,
    read_cowrie_logs,
)


def _line(session: str) -> str:
    return json.dumps(
        {
            "eventid": "cowrie.session.connect",
            "timestamp": "2026-11-09T12:00:00Z",
            "session": session,
            "src_ip": "127.0.0.1",
        }
    ) + "\n"


def _make_logs(tmp_path):
    current = tmp_path / "cowrie.json"
    old_a = tmp_path / "cowrie.json.2026-10-27"
    old_b = tmp_path / "cowrie.json.2026-10-28"
    compressed = tmp_path / "cowrie.json.2026-10-26.gz"
    current.write_text(_line("current"), encoding="utf-8")
    old_a.write_text(_line("old-a"), encoding="utf-8")
    old_b.write_text(_line("old-b"), encoding="utf-8")
    compressed.write_bytes(b"\x1f\x8b not text")
    return current, old_a, old_b, compressed


def test_find_log_files_lists_rotated_oldest_first_then_current(tmp_path):
    current, old_a, old_b, _ = _make_logs(tmp_path)
    assert find_log_files(current) == [old_a, old_b, current]


def test_find_log_files_skips_compressed_rotations(tmp_path):
    current, _, _, compressed = _make_logs(tmp_path)
    assert compressed not in find_log_files(current)


def test_find_log_files_can_ignore_rotated(tmp_path):
    current, *_ = _make_logs(tmp_path)
    assert find_log_files(current, include_rotated=False) == [current]


def test_read_cowrie_logs_reads_current_and_rotated(tmp_path):
    current, *_ = _make_logs(tmp_path)
    events, quarantined = read_cowrie_logs(current)
    assert len(events) == 3
    assert quarantined == 0
    assert len({event["event_id"] for event in events}) == 3


def test_read_cowrie_logs_without_rotated_reads_only_current(tmp_path):
    current, *_ = _make_logs(tmp_path)
    events, _ = read_cowrie_logs(current, include_rotated=False)
    assert len(events) == 1


def test_run_ids_are_attached_when_given(tmp_path):
    current, *_ = _make_logs(tmp_path)
    events, _ = read_cowrie_events(
        current, scenario_id="attack-basic", test_run_id="RUN-1"
    )
    assert events[0]["scenario_id"] == "attack-basic"
    assert events[0]["test_run_id"] == "RUN-1"


def test_run_ids_stay_none_by_default(tmp_path):
    current, *_ = _make_logs(tmp_path)
    events, _ = read_cowrie_events(current)
    assert events[0]["scenario_id"] is None
    assert events[0]["test_run_id"] is None