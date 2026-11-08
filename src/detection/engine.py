"""Moteur de détection : applique des règles à des événements normalisés."""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Optional

from src.detection.rules import DEFAULT_RULES, Rule

# Liste blanche : seuls ces champs peuvent entrer dans les preuves.
# Jamais raw_event, metadata ou message, pour ne pas copier de secrets.
SAFE_EVIDENCE_FIELDS = ("event_type", "session_id", "src_ip", "protocol", "username")


@dataclass(frozen=True)
class Detection:
    detection_id: str
    rule_id: str
    description: str
    severity: str
    source_event_ids: tuple
    evidence: dict = field(default_factory=dict)
    created_at: Optional[datetime] = None


def _is_valid_event(event) -> bool:
    """Un événement exploitable est un dict avec event_id et event_type non vides."""
    return (
        isinstance(event, dict)
        and isinstance(event.get("event_id"), str) and bool(event["event_id"])
        and isinstance(event.get("event_type"), str) and bool(event["event_type"])
    )


def _build_evidence(event: dict) -> dict:
    return {k: event[k] for k in SAFE_EVIDENCE_FIELDS if event.get(k) is not None}


def _detection_id(rule_id: str, event_ids: tuple) -> str:
    """ID déterministe : même règle + mêmes événements = même ID (sans created_at)."""
    raw = rule_id + "|" + ",".join(sorted(event_ids))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class DetectionEngine:
    def __init__(self, rules: Optional[Iterable[Rule]] = None):
        self.rules = tuple(DEFAULT_RULES if rules is None else rules)

    def analyze_event(self, event, now: Optional[datetime] = None) -> list:
        """Applique toutes les règles à un événement. Ignore les événements invalides."""
        if not _is_valid_event(event):
            return []
        created_at = now or datetime.now(timezone.utc)
        results = []
        for rule in self.rules:
            if rule.matches(event):
                event_ids = (event["event_id"],)
                results.append(
                    Detection(
                        detection_id=_detection_id(rule.rule_id, event_ids),
                        rule_id=rule.rule_id,
                        description=rule.description,
                        severity=rule.severity,
                        source_event_ids=event_ids,
                        evidence=_build_evidence(event),
                        created_at=created_at,
                    )
                )
        return results

    def analyze(self, events: Iterable, now: Optional[datetime] = None) -> list:
        """Analyse une liste d'événements et dédoublonne par detection_id."""
        seen = set()
        results = []
        for event in events:
            for detection in self.analyze_event(event, now=now):
                if detection.detection_id not in seen:
                    seen.add(detection.detection_id)
                    results.append(detection)
        return results