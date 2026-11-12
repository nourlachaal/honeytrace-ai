
"""Moteur de détection : applique des règles à des événements normalisés."""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Optional

from src.detection.rules import (
    DEFAULT_RULES,
    DEFAULT_SEQUENCE_RULES,
    DEFAULT_THRESHOLD_RULES,
    Rule,
    SequenceRule,
    ThresholdRule,
)

# Liste blanche : seuls ces champs peuvent entrer dans les preuves.
SAFE_EVIDENCE_FIELDS = (
    "event_type", "session_id", "src_ip", "protocol", "username",
    "http_method", "route", "status_code",
)

DETECTOR_VERSION = "1.0.0"

@dataclass(frozen=True)
class Detection:
    detection_id: str
    rule_id: str
    description: str
    severity: str
    source_event_ids: tuple
    evidence: dict = field(default_factory=dict)
    created_at: Optional[datetime] = None
    detector_version: str = DETECTOR_VERSION

def _is_valid_event(event) -> bool:
    return (
        isinstance(event, dict)
        and isinstance(event.get("event_id"), str) and bool(event["event_id"])
        and isinstance(event.get("event_type"), str) and bool(event["event_type"])
    )


def _build_evidence(event: dict) -> dict:
    return {k: event[k] for k in SAFE_EVIDENCE_FIELDS if event.get(k) is not None}


def _detection_id(rule_id: str, event_ids: tuple) -> str:
    raw = rule_id + "|" + ",".join(sorted(event_ids))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _aware_timestamp(event: dict) -> Optional[datetime]:
    """Retourne le timestamp s'il est un datetime avec fuseau, sinon None."""
    ts = event.get("event_timestamp")
    if isinstance(ts, datetime) and ts.tzinfo is not None:
        return ts
    return None


class DetectionEngine:
    def __init__(
        self,
        rules: Optional[Iterable[Rule]] = None,
        threshold_rules: Optional[Iterable[ThresholdRule]] = None,
        sequence_rules: Optional[Iterable[SequenceRule]] = None,
    ):
        self.rules = tuple(DEFAULT_RULES if rules is None else rules)
        self.threshold_rules = tuple(
            DEFAULT_THRESHOLD_RULES if threshold_rules is None else threshold_rules
        )
        self.sequence_rules = tuple(
            DEFAULT_SEQUENCE_RULES if sequence_rules is None else sequence_rules
        )

    def analyze_event(self, event, now: Optional[datetime] = None) -> list:
        """Règles simples : un événement -> zéro ou plusieurs détections."""
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

    def _analyze_threshold_rule(self, rule: ThresholdRule, events: list, created_at) -> list:
        """Règle à seuil : regroupe par session_id (jamais par IP)."""
        sessions = {}
        for event in events:
            if not _is_valid_event(event) or event["event_type"] not in rule.event_types:
                continue
            session_id = event.get("session_id")
            if not isinstance(session_id, str) or not session_id:
                continue  # sans session vérifiée, on ne relie rien
            ts = _aware_timestamp(event)
            if ts is None:
                continue
            # clé = event_id : un même événement vu deux fois ne compte qu'une fois
            sessions.setdefault(session_id, {})[event["event_id"]] = (ts, event)

        results = []
        n = rule.threshold
        for session_id in sorted(sessions):
            items = sorted(
                sessions[session_id].values(),
                key=lambda pair: (pair[0], pair[1]["event_id"]),
            )
            for i in range(len(items) - n + 1):
                window = items[i : i + n]
                span = (window[-1][0] - window[0][0]).total_seconds()
                if span <= rule.window_seconds:
                    event_ids = tuple(ev["event_id"] for _, ev in window)
                    evidence = {
                        "session_id": session_id,
                        "count": n,
                        "window_seconds": rule.window_seconds,
                        "first_event_at": window[0][0].isoformat(),
                        "last_event_at": window[-1][0].isoformat(),
                    }
                    if window[0][1].get("src_ip") is not None:
                        evidence["src_ip"] = window[0][1]["src_ip"]
                    results.append(
                        Detection(
                            detection_id=_detection_id(rule.rule_id, event_ids),
                            rule_id=rule.rule_id,
                            description=rule.description,
                            severity=rule.severity,
                            source_event_ids=event_ids,
                            evidence=evidence,
                            created_at=created_at,
                        )
                    )
                    break  # une seule détection par session et par règle
        return results

    def _analyze_sequence_rule(self, rule: SequenceRule, events: list, created_at) -> list:
        """N événements 'prior' puis un 'final', même session_id, dans la fenêtre."""
        relevant = rule.prior_types | rule.final_types
        sessions = {}
        for event in events:
            if not _is_valid_event(event) or event["event_type"] not in relevant:
                continue
            session_id = event.get("session_id")
            if not isinstance(session_id, str) or not session_id:
                continue
            ts = _aware_timestamp(event)
            if ts is None:
                continue
            sessions.setdefault(session_id, {})[event["event_id"]] = (ts, event)

        results = []
        for session_id in sorted(sessions):
            items = sorted(
                sessions[session_id].values(),
                key=lambda pair: (pair[0], pair[1]["event_id"]),
            )
            for final_ts, final_ev in items:
                if final_ev["event_type"] not in rule.final_types:
                    continue
                # Les 'prior' doivent être STRICTEMENT avant le 'final' et dans la fenêtre.
                priors = [
                    (ts, ev) for ts, ev in items
                    if ev["event_type"] in rule.prior_types
                    and ts < final_ts
                    and (final_ts - ts).total_seconds() <= rule.window_seconds
                ]
                if len(priors) < rule.prior_count:
                    continue
                chosen = priors[-rule.prior_count:]
                event_ids = tuple(ev["event_id"] for _, ev in chosen) + (final_ev["event_id"],)
                evidence = {
                    "session_id": session_id,
                    "prior_count": rule.prior_count,
                    "window_seconds": rule.window_seconds,
                    "first_event_at": chosen[0][0].isoformat(),
                    "last_event_at": final_ts.isoformat(),
                }
                if final_ev.get("src_ip") is not None:
                    evidence["src_ip"] = final_ev["src_ip"]
                if final_ev.get("username") is not None:
                    evidence["username"] = final_ev["username"]
                results.append(
                    Detection(
                        detection_id=_detection_id(rule.rule_id, event_ids),
                        rule_id=rule.rule_id,
                        description=rule.description,
                        severity=rule.severity,
                        source_event_ids=event_ids,
                        evidence=evidence,
                        created_at=created_at,
                    )
                )
                break  # une détection par session et par règle
        return results

    def analyze(self, events: Iterable, now: Optional[datetime] = None) -> list:
        """Applique règles simples, à seuil et de séquence ; dédoublonne par detection_id."""
        events = list(events)
        created_at = now or datetime.now(timezone.utc)
        seen = set()
        results = []

        def add(detection):
            if detection.detection_id not in seen:
                seen.add(detection.detection_id)
                results.append(detection)

        for event in events:
            for detection in self.analyze_event(event, now=created_at):
                add(detection)

        for rule in self.threshold_rules:
            for detection in self._analyze_threshold_rule(rule, events, created_at):
                add(detection)

        for rule in self.sequence_rules:
            for detection in self._analyze_sequence_rule(rule, events, created_at):
                add(detection)

        return results
