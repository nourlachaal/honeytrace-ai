
import json

from src.collectors.juice_shop_collector import read_juice_shop_events


def test_reads_valid_juice_shop_events(tmp_path, monkeypatch):
    log_file = tmp_path / "access.jsonl"
    quarantine_file = tmp_path / "quarantine.jsonl"

    monkeypatch.setattr(
        "src.collectors.juice_shop_collector.QUARANTINE_FILE",
        quarantine_file,
    )

    event = {
        "timestamp": "2026-10-27T23:52:44+00:00",
        "event_type": "juice_shop.http_request",
        "http_method": "GET",
        "route": "/",
        "status_code": 200,
        "src_ip": "127.0.0.1",
    }
    log_file.write_text(json.dumps(event) + "\n", encoding="utf-8")

    events, quarantined = read_juice_shop_events(log_file)

    assert len(events) == 1
    assert quarantined == 0
    assert events[0]["source"] == "juice_shop"
    assert events[0]["http_method"] == "GET"
    assert events[0]["status_code"] == 200


def test_quarantines_malformed_json(tmp_path, monkeypatch):
    log_file = tmp_path / "access.jsonl"
    quarantine_file = tmp_path / "quarantine.jsonl"

    monkeypatch.setattr(
        "src.collectors.juice_shop_collector.QUARANTINE_FILE",
        quarantine_file,
    )

    log_file.write_text("{invalid json}\n", encoding="utf-8")

    events, quarantined = read_juice_shop_events(log_file)

    assert events == []
    assert quarantined == 1
    assert quarantine_file.exists()
