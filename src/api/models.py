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
