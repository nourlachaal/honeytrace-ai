from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict


# API-facing event contract.
# Never add raw_event, metadata, command, message, or username here.
# See docs/api-field-policy.md.
class EventSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    source: Literal["cowrie", "juice_shop"]
    event_timestamp: datetime
    collected_at: datetime
    event_type: str
    session_id: str | None
    scenario_id: str | None
    test_run_id: str | None
    src_ip: str | None
    protocol: str | None
    http_method: str | None
    route: str | None
    status_code: int | None


class EventPage(BaseModel):
    items: list[EventSummary]
    next_cursor: str | None


# API-facing incident contract.
# Mirrors the column grants in sql/004 and section 7 of the integration
# contract. Never add evidence_internal, username, command, message,
# raw_event or metadata here.


class TimelineEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    event_id: str
    event_type: str
    source: str
    detection_ids: list[str] = []


class IncidentSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str
    source: str
    session_id: str
    title: str
    summary: str
    severity: Literal["low", "medium", "high", "critical"]
    status: Literal["open", "under_review", "resolved", "false_positive"]
    has_new_evidence: bool
    detection_ids: list[str]
    event_ids: list[str]
    missing_event_ids: list[str]
    timeline: list[TimelineEntry]
    created_at: datetime
    updated_at: datetime


class IncidentPage(BaseModel):
    items: list[IncidentSummary]
    next_cursor: str | None