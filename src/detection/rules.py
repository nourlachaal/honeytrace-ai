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