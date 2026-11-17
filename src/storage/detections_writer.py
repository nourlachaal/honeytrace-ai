"""Écriture des détections et incidents dans PostgreSQL (tables de sql/003).

- détections : INSERT ... ON CONFLICT DO NOTHING (append-only, jamais supprimées) ;
- incidents : seules les colonnes du moteur sont mises à jour, JAMAIS `status` ;
- has_new_evidence : passe à true seulement (jamais à false) quand de nouvelles
  détections arrivent sur un incident resolved / false_positive ;
- sévérité : monotone (en plus du trigger de sql/003).
"""

from typing import Iterable

from psycopg.types.json import Jsonb

from src.correlation.export import public_evidence, timeline_entry_to_dict

INSERT_DETECTION_SQL = """
INSERT INTO detections (
    detection_id, rule_id, description, severity, source_event_ids,
    evidence_public, evidence_internal, detector_version, created_at
) VALUES (
    %(detection_id)s, %(rule_id)s, %(description)s, %(severity)s,
    %(source_event_ids)s, %(evidence_public)s, %(evidence_internal)s,
    %(detector_version)s, %(created_at)s
)
ON CONFLICT (detection_id) DO NOTHING
"""

_HAS_NEW_DETECTIONS = (
    "EXISTS (SELECT 1 FROM unnest(EXCLUDED.detection_ids) AS d "
    "WHERE d <> ALL (incidents.detection_ids))"
)
_LOT_IS_COMPLETE = "cardinality(EXCLUDED.event_ids) >= cardinality(incidents.event_ids)"
_SEVERITY_RANK = "array_position(ARRAY['low','medium','high','critical'], {})"

UPSERT_INCIDENT_SQL = f"""
INSERT INTO incidents (
    incident_id, source, session_id, title, summary, severity,
    detection_ids, event_ids, missing_event_ids, timeline,
    created_at, updated_at
) VALUES (
    %(incident_id)s, %(source)s, %(session_id)s, %(title)s, %(summary)s,
    %(severity)s, %(detection_ids)s, %(event_ids)s, %(missing_event_ids)s,
    %(timeline)s, %(created_at)s, %(updated_at)s
)
ON CONFLICT (incident_id) DO UPDATE SET
    title = EXCLUDED.title,
    summary = EXCLUDED.summary,
    severity = CASE
        WHEN {_SEVERITY_RANK.format("EXCLUDED.severity")}
           > {_SEVERITY_RANK.format("incidents.severity")}
        THEN EXCLUDED.severity ELSE incidents.severity END,
    detection_ids = ARRAY(
        SELECT DISTINCT d
          FROM unnest(incidents.detection_ids || EXCLUDED.detection_ids) AS d
         ORDER BY d),
    event_ids = CASE WHEN {_LOT_IS_COMPLETE}
        THEN EXCLUDED.event_ids ELSE incidents.event_ids END,
    missing_event_ids = CASE WHEN {_LOT_IS_COMPLETE}
        THEN EXCLUDED.missing_event_ids ELSE incidents.missing_event_ids END,
    timeline = CASE WHEN {_LOT_IS_COMPLETE}
        THEN EXCLUDED.timeline ELSE incidents.timeline END,
    has_new_evidence = incidents.has_new_evidence
        OR (incidents.status IN ('resolved', 'false_positive')
            AND {_HAS_NEW_DETECTIONS}),
    updated_at = CASE WHEN {_HAS_NEW_DETECTIONS}
        THEN EXCLUDED.updated_at ELSE incidents.updated_at END
"""


def detection_params(detection) -> dict:
    return {
        "detection_id": detection.detection_id,
        "rule_id": detection.rule_id,
        "description": detection.description,
        "severity": detection.severity,
        "source_event_ids": list(detection.source_event_ids),
        "evidence_public": Jsonb(public_evidence(detection.evidence)),
        "evidence_internal": Jsonb(dict(detection.evidence)),
        "detector_version": detection.detector_version,
        "created_at": detection.created_at,
    }


def incident_params(incident) -> dict:
    # Ni `status` ni `has_new_evidence` : valeurs par défaut de la table.
    return {
        "incident_id": incident.incident_id,
        "source": incident.source,
        "session_id": incident.session_id,
        "title": incident.title,
        "summary": incident.summary,
        "severity": incident.severity,
        "detection_ids": list(incident.detection_ids),
        "event_ids": list(incident.event_ids),
        "missing_event_ids": list(incident.missing_event_ids),
        "timeline": Jsonb([timeline_entry_to_dict(e) for e in incident.timeline]),
        "created_at": incident.created_at,
        "updated_at": incident.updated_at,
    }


def _storable(incident) -> bool:
    """sql/003 refuse '|' dans source et session_id (séparateur de incident_id)."""
    return "|" not in incident.source and "|" not in incident.session_id


def write_results(connection, detections: Iterable, incidents: Iterable) -> dict:
    """Écrit détections puis incidents dans UNE transaction (tout ou rien)."""
    incidents = list(incidents)
    storable = [i for i in incidents if _storable(i)]
    inserted = 0
    with connection.transaction():
        with connection.cursor() as cursor:
            for detection in detections:
                cursor.execute(INSERT_DETECTION_SQL, detection_params(detection))
                inserted += max(cursor.rowcount, 0)
            for incident in storable:
                cursor.execute(UPSERT_INCIDENT_SQL, incident_params(incident))
    return {
        "detections_inserted": inserted,
        "incidents_upserted": len(storable),
        "incidents_skipped": len(incidents) - len(storable),
    }