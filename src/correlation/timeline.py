"""Timeline : événements d'un incident, en ordre chronologique, avec références."""

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable


@dataclass(frozen=True)
class TimelineEntry:
    timestamp: datetime
    event_id: str
    event_type: str
    source: str
    detection_ids: tuple = ()


def build_timeline(events: Iterable, detections: Iterable = ()) -> tuple:
    """Construit la timeline à partir d'événements DÉJÀ reliés (même session).

    - ignore les événements invalides ou sans timestamp avec fuseau ;
    - un même event_id n'apparaît qu'une fois ;
    - tri par (timestamp, event_id) : le résultat ne dépend pas de l'ordre d'entrée ;
    - aucune commande ni message n'est copié : seulement des références.
    """
    detection_ids_by_event = {}
    for detection in detections:
        for event_id in detection.source_event_ids:
            detection_ids_by_event.setdefault(event_id, set()).add(detection.detection_id)

    entries = {}
    for event in events:
        if not isinstance(event, dict):
            continue
        event_id = event.get("event_id")
        if not isinstance(event_id, str) or not event_id:
            continue
        timestamp = event.get("event_timestamp")
        if not isinstance(timestamp, datetime) or timestamp.tzinfo is None:
            continue
        event_type = event.get("event_type")
        source = event.get("source")
        entries[event_id] = TimelineEntry(
            timestamp=timestamp,
            event_id=event_id,
            event_type=event_type if isinstance(event_type, str) else "unknown",
            source=source if isinstance(source, str) else "unknown",
            detection_ids=tuple(sorted(detection_ids_by_event.get(event_id, ()))),
        )

    return tuple(sorted(entries.values(), key=lambda e: (e.timestamp, e.event_id)))