"""Export JSON des détections et des incidents.

Par défaut, l'export est PUBLIC : `evidence` est une projection qui ne contient
que des champs autorisés (jamais `username`). `internal=True` ajoute
`evidence_internal` (blob complet), destiné au stockage en base uniquement.
"""

import json
from datetime import datetime
from typing import Iterable, Optional

# Champs d'evidence qu'une API peut servir. `username` en est exclu volontairement.
PUBLIC_EVIDENCE_FIELDS = (
    "event_type", "session_id", "src_ip", "protocol",
    "http_method", "route", "status_code",
    "count", "window_seconds", "prior_count",
    "first_event_at", "last_event_at",
)


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if isinstance(value, datetime) else None


def public_evidence(evidence: dict) -> dict:
    """Projection de l'evidence : uniquement les champs de la liste blanche."""
    return {k: evidence[k] for k in PUBLIC_EVIDENCE_FIELDS if k in evidence}


def detection_to_dict(detection, internal: bool = False) -> dict:
    data = {
        "detection_id": detection.detection_id,
        "rule_id": detection.rule_id,
        "description": detection.description,
        "severity": detection.severity,
        "source_event_ids": list(detection.source_event_ids),
        "evidence": public_evidence(detection.evidence),
        "created_at": _iso(detection.created_at),
        "detector_version": detection.detector_version,
    }
    if internal:
        data["evidence_internal"] = dict(detection.evidence)
    return data


def timeline_entry_to_dict(entry) -> dict:
    return {
        "timestamp": _iso(entry.timestamp),
        "event_id": entry.event_id,
        "event_type": entry.event_type,
        "source": entry.source,
        "detection_ids": list(entry.detection_ids),
    }


def incident_to_dict(incident) -> dict:
    return {
        "incident_id": incident.incident_id,
        "title": incident.title,
        "summary": incident.summary,
        "severity": incident.severity,
        "status": incident.status,
        "created_at": _iso(incident.created_at),
        "updated_at": _iso(incident.updated_at),
        "source": incident.source,
        "session_id": incident.session_id,
        "detection_ids": list(incident.detection_ids),
        "event_ids": list(incident.event_ids),
        "missing_event_ids": list(incident.missing_event_ids),
        "timeline": [timeline_entry_to_dict(e) for e in incident.timeline],
    }


def export_results(detections: Iterable, incidents: Iterable, internal: bool = False) -> dict:
    """Structure complète, triée pour être déterministe."""
    return {
        "detections": [
            detection_to_dict(d, internal=internal)
            for d in sorted(detections, key=lambda d: d.detection_id)
        ],
        "incidents": [
            incident_to_dict(i)
            for i in sorted(incidents, key=lambda i: i.incident_id)
        ],
    }


def export_json(detections: Iterable, incidents: Iterable, internal: bool = False) -> str:
    return json.dumps(
        export_results(detections, incidents, internal=internal),
        sort_keys=True,
        ensure_ascii=False,
        indent=2,
    )