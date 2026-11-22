
import hashlib
import json
from datetime import datetime, timezone
from typing import Any

SENSITIVE_KEYS = {
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "private_key",
    "privatekey",
    "key",
    "credential",
    "credentials",
}

KNOWN_COLUMNS = {
    "session",
    "protocol",
    "src_ip",
    "eventid",
    "timestamp",
    "message",
    "username",
    "command",
    "sensor",
    "uuid",
    "id",
    "event_uid",
    "src_port",
    "dst_ip",
    "dst_port",
    "duration_ms",
    "version",
    "hassh",
    "hasshAlgorithms",
    "kexAlgs",
    "keyAlgs",
    "encCS",
    "macCS",
    "compCS",
    "langCS",
    "width",
    "height",
    "fingerprint",
    "type",
    "event_type",
    "http_method",
    "route",
    "status_code",
    "input",
}


def _sanitize(value: Any) -> Any:
    """Recursively redact sensitive values in dictionaries and lists."""
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            if key.lower() in SENSITIVE_KEYS:
                cleaned[key] = "[REDACTED]"
            else:
                cleaned[key] = _sanitize(item)
        return cleaned

    if isinstance(value, list):
        return [_sanitize(item) for item in value]

    return value


def _parse_timestamp(value: Any) -> datetime:
    """Parse a source timestamp and return an aware UTC datetime."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Missing or invalid event timestamp")

    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError("Invalid event timestamp") from exc

    if parsed.tzinfo is None:
        # Source timestamps without a timezone are ambiguous.
        raise ValueError("Event timestamp has no timezone")

    return parsed.astimezone(timezone.utc)


def normalize_event(
    raw_event: dict[str, Any],
    source: str = "cowrie",
    scenario_id: str | None = None,
    test_run_id: str | None = None,
) -> dict[str, Any]:
    """
    Normalize one source event to the HoneyTrace PostgreSQL schema.

    Raises ValueError for malformed or unsupported input.
    """
    if not isinstance(raw_event, dict):
        raise ValueError("Event must be a JSON object")

    if source not in {"cowrie", "juice_shop"}:
        raise ValueError("Unsupported event source")

    event_timestamp = _parse_timestamp(raw_event.get("timestamp"))

    event_type = raw_event.get("eventid") or raw_event.get("event_type")
    if not isinstance(event_type, str) or not event_type.strip():
        raise ValueError("Missing event type")

    # Hash the original event so identical source records get the same ID.
    # The digest does not expose the original credential values.
    canonical = json.dumps(
        {"source": source, "event": raw_event},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    event_id = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    safe_raw = _sanitize(raw_event)

    metadata = {
        key: value
        for key, value in safe_raw.items()
        if key not in KNOWN_COLUMNS
    }

    username = safe_raw.get("username")
    command = safe_raw.get("input") or safe_raw.get("command")
    message = safe_raw.get("message")
    src_ip = safe_raw.get("src_ip")
    protocol = safe_raw.get("protocol")

    return {
        "event_id": event_id,
        "source": source,
        "source_event_id": safe_raw.get("id") or safe_raw.get("event_uid"),
        "event_timestamp": event_timestamp,
        "event_type": event_type,
        "session_id": safe_raw.get("session_id") or safe_raw.get("session"),
        "scenario_id": scenario_id,
        "test_run_id": test_run_id,
        "src_ip": src_ip,
        "protocol": protocol,
        "username": username,
        "command": command,
        "http_method": safe_raw.get("http_method"),
        "route": safe_raw.get("route"),
        "status_code": safe_raw.get("status_code"),
        "message": message,
        "metadata": metadata,
        "raw_event": safe_raw,
    }
