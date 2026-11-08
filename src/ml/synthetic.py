"""Sessions Cowrie SYNTHÉTIQUES, pour tester le code ML uniquement.

Ces données ne permettent AUCUNE conclusion sur les performances réelles.
Chaque événement porte scenario_id = "SYNTHETIC".
"""

import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

SYNTHETIC_SCENARIO_ID = "SYNTHETIC"
BASE_TIME = datetime(2026, 11, 1, 8, 0, 0, tzinfo=timezone.utc)
SOURCE = "cowrie"

NOISY_NORMAL_SHARE = 0.25      # part des sessions normales "bruyantes"
DISCREET_ATTACK_SHARE = 0.35   # part des attaques "discrètes"

USERNAMES = ("root", "admin", "user", "test", "oracle", "pi", "ubuntu", "guest")


@dataclass(frozen=True)
class SyntheticDataset:
    events: list    # événements au format normalisé (dicts)
    labels: dict    # (source, session_id) -> 1 (attaque) ou 0 (normal)
    kinds: dict     # (source, session_id) -> nom du type de session


def _session_plan(rng: random.Random, kind: str) -> tuple:
    """Retourne (gap_min, gap_max, n_failed, has_success, n_commands, fixed_user)."""
    if kind == "normal_quiet":
        return 2.0, 20.0, rng.randint(0, 1), True, rng.randint(1, 5), True
    if kind == "normal_noisy":
        return 3.0, 15.0, rng.randint(2, 4), True, rng.randint(3, 10), True
    if kind == "attack_obvious":
        has_success = rng.random() < 0.5
        n_commands = rng.randint(0, 8) if has_success else 0
        return 0.2, 2.0, rng.randint(8, 30), has_success, n_commands, False
    if kind == "attack_discreet":
        return 1.0, 5.0, rng.randint(2, 4), True, rng.randint(2, 6), False
    raise ValueError(f"Unknown session kind: {kind}")


def _make_session(rng, kind, seed, index, start, ip) -> list:
    gap_min, gap_max, n_failed, has_success, n_commands, fixed_user = _session_plan(rng, kind)
    session_id = f"syn-{seed}-{index:04d}"
    user = rng.choice(USERNAMES)

    steps = [("cowrie.session.connect", None)]
    steps += [("cowrie.login.failed", user if fixed_user else rng.choice(USERNAMES))
              for _ in range(n_failed)]
    if has_success:
        steps.append(("cowrie.login.success", user if fixed_user else rng.choice(USERNAMES)))
    steps += [("cowrie.command.input", None) for _ in range(n_commands)]
    steps.append(("cowrie.session.closed", None))

    events = []
    current = start
    for k, (event_type, username) in enumerate(steps):
        if k > 0:
            current = current + timedelta(seconds=round(rng.uniform(gap_min, gap_max), 3))
        event = {
            "event_id": f"syn-{seed}-{index:04d}-{k:03d}",
            "source": SOURCE,
            "event_type": event_type,
            "session_id": session_id,
            "scenario_id": SYNTHETIC_SCENARIO_ID,
            "test_run_id": f"SYNTHETIC-{seed}",
            "src_ip": ip,
            "event_timestamp": current,
        }
        if username is not None:
            event["username"] = username
        events.append(event)
    return events


def generate_dataset(
    n_sessions: int = 200,
    attack_ratio: float = 0.15,
    seed: int = 42,
) -> SyntheticDataset:
    """Génère n_sessions sessions, de façon reproductible pour une graine donnée."""
    if not isinstance(n_sessions, int) or n_sessions < 1:
        raise ValueError("n_sessions must be a positive integer")
    if not 0.0 <= attack_ratio <= 1.0:
        raise ValueError("attack_ratio must be between 0 and 1")

    rng = random.Random(seed)

    n_attacks = round(n_sessions * attack_ratio)
    if attack_ratio > 0 and n_attacks == 0:
        n_attacks = 1  # au moins une attaque, sinon Recall n'a pas de sens
    n_attacks = min(n_attacks, n_sessions)
    attack_indices = set(rng.sample(range(n_sessions), n_attacks))

    events, labels, kinds = [], {}, {}
    for i in range(n_sessions):
        if i in attack_indices:
            kind = "attack_discreet" if rng.random() < DISCREET_ATTACK_SHARE else "attack_obvious"
        else:
            kind = "normal_noisy" if rng.random() < NOISY_NORMAL_SHARE else "normal_quiet"

        start = BASE_TIME + timedelta(minutes=10 * i)
        ip = f"192.0.2.{rng.randint(1, 254)}"   # plage réservée à la documentation
        events.extend(_make_session(rng, kind, seed, i, start, ip))

        key = (SOURCE, f"syn-{seed}-{i:04d}")
        labels[key] = 1 if i in attack_indices else 0
        kinds[key] = kind

    return SyntheticDataset(events=events, labels=labels, kinds=kinds)