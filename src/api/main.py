from datetime import datetime
from typing import Annotated, Literal

from fastapi import FastAPI, HTTPException, Query, Response, status

from src.api.database import database_status
from src.api.events import (
    CursorError,
    DatabaseNotConfigured,
    DatabaseUnavailable,
    decode_cursor,
    encode_cursor,
    fetch_events,
)
from src.api.models import EventPage

app = FastAPI(
    title="HoneyTrace AI API",
    description="Read-only API for normalized security events and incidents.",
    version="0.1.0",
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/db")
def health_db(response: Response) -> dict[str, str]:
    result = database_status()
    if result != "ok":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {"status": result}


@app.get("/events", response_model=EventPage)
def list_events(
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    source: Annotated[Literal["cowrie", "juice_shop"] | None, Query()] = None,
    event_type: Annotated[str | None, Query(max_length=100)] = None,
    src_ip: Annotated[str | None, Query(max_length=64)] = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> EventPage:
    for value in (since, until):
        if value is not None and value.tzinfo is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="timestamp_must_include_timezone",
            )

    decoded_cursor = None
    if cursor is not None:
        try:
            decoded_cursor = decode_cursor(cursor)
        except CursorError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="invalid_cursor",
            ) from None

    try:
        rows = fetch_events(
            limit=limit,
            cursor=decoded_cursor,
            source=source,
            event_type=event_type,
            src_ip=src_ip,
            since=since,
            until=until,
        )
    except DatabaseNotConfigured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="database_not_configured",
        ) from None
    except DatabaseUnavailable:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="database_unavailable",
        ) from None

    items = rows[:limit]
    next_cursor = None
    if len(rows) > limit and items:
        last = items[-1]
        next_cursor = encode_cursor(last["event_timestamp"], last["event_id"])

    return EventPage(items=items, next_cursor=next_cursor)
