"""Corrélation : regroupe des détections en incidents candidats, par session vérifiée.

Règle de sécurité : une adresse IP ne relie JAMAIS deux événements.
"""

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Optional

from src.correlation.timeline import build_timeline
from src.detection.rules import SEVERITIES

_RANK = {name: index for index, name in enumerate(SEVERITIES)}


@dataclass(frozen=True)
class Incident:
    incident_id: str
    title: str
    summary: str
    severity: str
    status: str
    created_at: datetime
    updated_at: datetime
    source: str
    session_id: str
    detection_ids: tuple
    event_ids: tuple
    missing_event_ids: tuple
    timeline: tuple


def _incident_id(source: str, session_id: str) -> str:
    """Stable : dépend seulement de la source et de la session."""
    raw = f"incident|{source}|{session_id}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _source_of(event: dict) -> str:
    source = event.get("source")
    return source if isinstance(source, str) and source else "unknown"


def _verified_key(detection, index: dict):
    """Retourne (source, session_id) si la détection est reliée à une session
    PROUVÉE par les événements qu'elle cite, sinon None."""
    evidence = detection.evidence if isinstance(detection.evidence, dict) else {}
    session_id = evidence.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        return None

    sources = set()
    for event_id in detection.source_event_ids:
        event = index.get(event_id)
        if event is None:
            continue  # événement absent : noté plus tard dans missing_event_ids
        if event.get("session_id") != session_id:
            return None  # contradiction : on ne relie rien
        sources.add(_source_of(event))

    if len(sources) != 1:
        return None  # aucun événement vérifiable, ou sources mélangées
    return next(iter(sources)), session_id


class IncidentCorrelator:
    def __init__(self, min_severity: str = "medium"):
        if min_severity not in _RANK:
            raise ValueError(f"Invalid severity: {min_severity}")
        self.min_severity = min_severity

    def correlate(
        self,
        detections: Iterable,
        events: Iterable,
        now: Optional[datetime] = None,
    ) -> list:
        now = now or datetime.now(timezone.utc)

        # Index des événements valides, et regroupement par (source, session_id).
        index = {}
        for event in events:
            if isinstance(event, dict) and isinstance(event.get("event_id"), str) \
                    and event["event_id"]:
                index[event["event_id"]] = event

        events_by_session = {}
        for event in index.values():
            session_id = event.get("session_id")
            if isinstance(session_id, str) and session_id:
                events_by_session.setdefault((_source_of(event), session_id), []).append(event)

        # Détections regroupées par session vérifiée (dédoublonnées par detection_id).
        groups = {}
        for detection in detections:
            key = _verified_key(detection, index)
            if key is not None:
                groups.setdefault(key, {})[detection.detection_id] = detection

        incidents = []
        for (source, session_id), by_id in groups.items():
            members = list(by_id.values())
            severity = max((d.severity for d in members), key=lambda s: _RANK[s])
            if _RANK[severity] < _RANK[self.min_severity]:
                continue

            timeline = build_timeline(events_by_session.get((source, session_id), []), members)
            known_ids = {entry.event_id for entry in timeline}
            cited = {eid for d in members for eid in d.source_event_ids}
            missing = tuple(sorted(eid for eid in cited if eid not in index))

            rule_ids = sorted({d.rule_id for d in members})
            incidents.append(
                Incident(
                    incident_id=_incident_id(source, session_id),
                    title=f"Suspicious activity in session {session_id}",
                    summary=(
                        f"{len(members)} detection(s) ({', '.join(rule_ids)}) "
                        f"linked by session over {len(known_ids)} event(s)."
                    ),
                    severity=severity,
                    status="open",
                    created_at=now,
                    updated_at=now,
                    source=source,
                    session_id=session_id,
                    detection_ids=tuple(sorted(by_id)),
                    event_ids=tuple(entry.event_id for entry in timeline),
                    missing_event_ids=missing,
                    timeline=timeline,
                )
            )

        incidents.sort(key=lambda i: (-_RANK[i.severity], i.incident_id))
        return incidents