"""Règles de détection. Une règle décrit QUOI chercher, pas comment l'exécuter."""

from dataclasses import dataclass
import re
from typing import Optional
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

# ---------------------------------------------------------------------------
# Étape 1.4 : commandes Cowrie et requêtes HTTP Juice Shop
# ---------------------------------------------------------------------------

# Borne de sécurité : on n'applique les regex que sur le début de la commande.
MAX_COMMAND_LENGTH = 2000


def _ci(pattern: str):
    """Compile une regex insensible à la casse."""
    return re.compile(pattern, re.IGNORECASE)


def _command_text(event: dict) -> Optional[str]:
    """Texte de la commande : champ `command`, sinon `metadata["input"]`.

    Cowrie stocke normalement la commande dans `input`. Le normalisateur
    actuel ne le met pas dans `command`, donc `input` finit dans `metadata`.
    """
    command = event.get("command")
    if isinstance(command, str) and command.strip():
        return command[:MAX_COMMAND_LENGTH]
    metadata = event.get("metadata")
    if isinstance(metadata, dict):
        value = metadata.get("input")
        if isinstance(value, str) and value.strip():
            return value[:MAX_COMMAND_LENGTH]
    return None


@dataclass(frozen=True)
class CommandRule:
    """Règle sur le contenu d'une commande. Le texte de la commande n'est
    JAMAIS copié dans les preuves : seul le rule_id indique la catégorie."""

    rule_id: str
    description: str
    severity: str
    event_types: frozenset
    patterns: tuple  # regex déjà compilées

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError(f"Invalid severity: {self.severity}")
        if not self.patterns:
            raise ValueError("patterns must not be empty")

    def matches(self, event: dict) -> bool:
        if event.get("event_type") not in self.event_types:
            return False
        text = _command_text(event)
        if text is None:
            return False
        return any(p.search(text) for p in self.patterns)


def _route_matches(route, prefixes) -> bool:
    """Vrai si la route égale un préfixe ou en est un sous-chemin.
    '/ftp' correspond à '/ftp' et '/ftp/x', mais pas à '/ftpx'."""
    if not isinstance(route, str):
        return False
    path = route.lower()
    return any(path == p or path.startswith(p + "/") for p in prefixes)


@dataclass(frozen=True)
class HttpRule:
    """Règle sur les champs HTTP (méthode, route, statut) d'un événement."""

    rule_id: str
    description: str
    severity: str
    event_types: frozenset
    methods: Optional[frozenset] = None          # ex. frozenset({"POST"}), en majuscules
    route_prefixes: tuple = ()                   # en minuscules, sans '/' final
    status_codes: Optional[frozenset] = None

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError(f"Invalid severity: {self.severity}")
        if self.methods is None and not self.route_prefixes and self.status_codes is None:
            raise ValueError("at least one condition is required")

    def matches(self, event: dict) -> bool:
        if event.get("event_type") not in self.event_types:
            return False

        if self.methods is not None:
            method = event.get("http_method")
            if not isinstance(method, str) or method.upper() not in self.methods:
                return False

        if self.route_prefixes and not _route_matches(event.get("route"), self.route_prefixes):
            return False

        if self.status_codes is not None:
            status = event.get("status_code")
            if isinstance(status, bool) or not isinstance(status, int):
                return False
            if status not in self.status_codes:
                return False

        return True


_COWRIE_COMMAND = frozenset({"cowrie.command.input"})

COWRIE_CMD_DOWNLOAD_TOOL = CommandRule(
    rule_id="COWRIE_CMD_DOWNLOAD_TOOL",
    description="Command using a download tool (possible payload retrieval).",
    severity="medium",
    event_types=_COWRIE_COMMAND,
    patterns=(_ci(r"\b(wget|curl|tftp|ftpget)\b"),),
)

COWRIE_CMD_PIPE_TO_SHELL = CommandRule(
    rule_id="COWRIE_CMD_PIPE_TO_SHELL",
    description="Downloaded content piped directly into a shell.",
    severity="high",
    event_types=_COWRIE_COMMAND,
    patterns=(_ci(r"\b(wget|curl)\b[^|]*\|\s*(ba|z|da)?sh\b"),),
)

COWRIE_CMD_CHMOD_EXEC = CommandRule(
    rule_id="COWRIE_CMD_CHMOD_EXEC",
    description="Command making a file executable.",
    severity="medium",
    event_types=_COWRIE_COMMAND,
    patterns=(_ci(r"\bchmod\s+(-\w+\s+)?([augo]*\+x|7[0-7]{2})\b"),),
)

_JUICE_REQUEST = frozenset({"juice_shop.http_request"})

JUICE_LOGIN_FAILED = HttpRule(
    rule_id="JUICE_LOGIN_FAILED",
    description="Failed login request (HTTP 401) on the Juice Shop login endpoint.",
    severity="low",
    event_types=_JUICE_REQUEST,
    methods=frozenset({"POST"}),
    route_prefixes=("/rest/user/login",),
    status_codes=frozenset({401}),
)

JUICE_SENSITIVE_ROUTE_SERVED = HttpRule(
    rule_id="JUICE_SENSITIVE_ROUTE_SERVED",
    description="Sensitive Juice Shop route successfully served.",
    severity="medium",
    event_types=_JUICE_REQUEST,
    methods=frozenset({"GET"}),
    route_prefixes=("/ftp", "/encryptionkeys", "/support/logs", "/metrics"),
    status_codes=frozenset(range(200, 300)),
)

JUICE_SERVER_ERROR = HttpRule(
    rule_id="JUICE_SERVER_ERROR",
    description="Server error (HTTP 500), possibly caused by malformed input.",
    severity="low",
    event_types=_JUICE_REQUEST,
    status_codes=frozenset({500}),
)

# Les règles simples par défaut = règle 1.1 + toutes les règles de cette étape.
DEFAULT_RULES = DEFAULT_RULES + (
    COWRIE_CMD_DOWNLOAD_TOOL,
    COWRIE_CMD_PIPE_TO_SHELL,
    COWRIE_CMD_CHMOD_EXEC,
    JUICE_LOGIN_FAILED,
    JUICE_SENSITIVE_ROUTE_SERVED,
    JUICE_SERVER_ERROR,
)