"""Contract tests for the API's public field allowlist.

The 13 names below are the approved contract from docs/api-field-policy.md.
They are hardcoded on purpose: importing them from the implementation would
let a widened contract update its own test.
"""

import json

from src.api.main import app
from src.api.models import EventPage, EventSummary

APPROVED_FIELDS = {
    "event_id",
    "source",
    "event_timestamp",
    "collected_at",
    "event_type",
    "session_id",
    "scenario_id",
    "test_run_id",
    "src_ip",
    "protocol",
    "http_method",
    "route",
    "status_code",
}

FORBIDDEN_FIELDS = ("raw_event", "metadata", "command", "message", "username")


def test_event_summary_exposes_exactly_the_approved_fields() -> None:
    assert set(EventSummary.model_fields) == APPROVED_FIELDS


def test_event_summary_rejects_unknown_fields() -> None:
    assert EventSummary.model_config.get("extra") == "forbid"


def test_event_page_adds_no_event_fields() -> None:
    assert set(EventPage.model_fields) == {"items", "next_cursor"}


def test_openapi_document_never_mentions_forbidden_fields() -> None:
    document = json.dumps(app.openapi())

    for field in FORBIDDEN_FIELDS:
        assert field not in document, f"{field} leaked into the OpenAPI document"
