"""Règles de détection. Une règle décrit QUOI chercher, pas comment l'exécuter."""

from dataclasses import dataclass

SEVERITIES = ("low", "medium", "high", "critical")


@dataclass(frozen=True)
class Rule:
    rule_id: str
    description: str
    severity: str
    event_types: frozenset

    def __post_init__(self):
        # Refuse une sévérité hors contrat dès la création de la règle.
        if self.severity not in SEVERITIES:
            raise ValueError(f"Invalid severity: {self.severity}")

    def matches(self, event: dict) -> bool:
        """Vrai si le type de l'événement fait partie de ceux surveillés."""
        return event.get("event_type") in self.event_types


COWRIE_LOGIN_FAILED = Rule(
    rule_id="COWRIE_LOGIN_FAILED",
    description="Failed SSH/Telnet login attempt observed on the Cowrie honeypot.",
    severity="low",  # un échec isolé n'est pas une attaque confirmée
    event_types=frozenset({"cowrie.login.failed"}),
)

DEFAULT_RULES = (COWRIE_LOGIN_FAILED,)

@dataclass(frozen=True)
class ThresholdRule:
    """Règle qui se déclenche quand `threshold` événements du même type
    surviennent dans une même session en moins de `window_seconds`."""

    rule_id: str
    description: str
    severity: str
    event_types: frozenset
    threshold: int
    window_seconds: int

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError(f"Invalid severity: {self.severity}")
        if self.threshold < 2:
            raise ValueError("threshold must be at least 2")
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")


COWRIE_BRUTE_FORCE = ThresholdRule(
    rule_id="COWRIE_BRUTE_FORCE_SESSION",
    description="Repeated failed logins within a single Cowrie session.",
    severity="medium",
    event_types=frozenset({"cowrie.login.failed"}),
    threshold=5,
    window_seconds=60,
)

DEFAULT_THRESHOLD_RULES = (COWRIE_BRUTE_FORCE,)

@dataclass(frozen=True)
class SequenceRule:
    """N événements 'prior' suivis d'un événement 'final', dans une même session."""

    rule_id: str
    description: str
    severity: str
    prior_types: frozenset
    prior_count: int
    final_types: frozenset
    window_seconds: int

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError(f"Invalid severity: {self.severity}")
        if self.prior_count < 1:
            raise ValueError("prior_count must be at least 1")
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if self.prior_types & self.final_types:
            raise ValueError("prior_types and final_types must be disjoint")


COWRIE_SUCCESS_AFTER_FAILURES = SequenceRule(
    rule_id="COWRIE_SUCCESS_AFTER_FAILURES",
    description="Successful login after repeated failures in the same Cowrie session.",
    severity="high",
    prior_types=frozenset({"cowrie.login.failed"}),
    prior_count=3,
    final_types=frozenset({"cowrie.login.success"}),
    window_seconds=300,
)

DEFAULT_SEQUENCE_RULES = (COWRIE_SUCCESS_AFTER_FAILURES,)