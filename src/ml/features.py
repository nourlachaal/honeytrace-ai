"""Features numériques par session, calculées uniquement à partir des événements.

Aucun texte (commande, message, mot de passe, IP) n'entre dans les features.
Aucune sortie de règle de détection n'est utilisée : cela évite une fuite
de données entre la détection par règles et le ML.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

LOGIN_FAILED = "cowrie.login.failed"
LOGIN_SUCCESS = "cowrie.login.success"
COMMAND_INPUT = "cowrie.command.input"

FEATURE_NAMES = (
    "event_count",
    "login_failed_count",
    "login_success_count",
    "command_count",
    "distinct_event_types",
    "distinct_usernames",
    "duration_seconds",
    "events_per_second",
    "failed_login_ratio",
)


@dataclass(frozen=True)
class SessionFeatures:
    source: str
    session_id: str
    values: dict

    def vector(self) -> list:
        """Valeurs numériques dans l'ordre fixe de FEATURE_NAMES."""
        return [float(self.values[name]) for name in FEATURE_NAMES]


def _usable(event):
    """Retourne (source, session_id, event_id, timestamp) ou None si inexploitable."""
    if not isinstance(event, dict):
        return None
    event_id = event.get("event_id")
    session_id = event.get("session_id")
    timestamp = event.get("event_timestamp")
    if not isinstance(event_id, str) or not event_id:
        return None
    if not isinstance(session_id, str) or not session_id:
        return None
    if not isinstance(timestamp, datetime) or timestamp.tzinfo is None:
        return None
    source = event.get("source")
    if not isinstance(source, str) or not source:
        source = "unknown"
    return source, session_id, event_id, timestamp


def _compute(events: list) -> dict:
    types = [e.get("event_type") for e in events]
    failed = sum(1 for t in types if t == LOGIN_FAILED)
    success = sum(1 for t in types if t == LOGIN_SUCCESS)
    commands = sum(1 for t in types if t == COMMAND_INPUT)

    timestamps = [e["event_timestamp"] for e in events]
    duration = (max(timestamps) - min(timestamps)).total_seconds()

    usernames = {
        e["username"] for e in events
        if isinstance(e.get("username"), str) and e["username"]
    }
    attempts = failed + success

    return {
        "event_count": len(events),
        "login_failed_count": failed,
        "login_success_count": success,
        "command_count": commands,
        "distinct_event_types": len({t for t in types if isinstance(t, str)}),
        "distinct_usernames": len(usernames),
        "duration_seconds": duration,
        # max(durée, 1) évite la division par zéro pour les sessions très courtes
        "events_per_second": len(events) / max(duration, 1.0),
        "failed_login_ratio": (failed / attempts) if attempts else 0.0,
    }


def build_session_features(events: Iterable) -> list:
    """Une SessionFeatures par (source, session_id), triées pour être déterministes."""
    sessions = {}
    for event in events:
        info = _usable(event)
        if info is None:
            continue
        source, session_id, event_id, _ = info
        # clé = event_id : un même événement vu deux fois compte une seule fois
        sessions.setdefault((source, session_id), {})[event_id] = event

    return [
        SessionFeatures(source, session_id, _compute(list(sessions[(source, session_id)].values())))
        for source, session_id in sorted(sessions)
    ]