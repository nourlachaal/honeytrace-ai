"""Regroupement de sessions par DBSCAN (exploratoire).

DBSCAN n'est PAS un classificateur d'attaques : les clusters s'interprètent
avec les features et les scénarios connus. Le label -1 signifie "bruit"
(session sans voisinage dense), pas "attaque".
"""

from dataclasses import dataclass
from typing import Iterable, Optional

import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import StandardScaler

NOISE = -1
MIN_SESSIONS = 20


@dataclass(frozen=True)
class ClusterAssignment:
    source: str
    session_id: str
    cluster: int   # -1 = bruit


@dataclass(frozen=True)
class ClusteringResult:
    assignments: tuple
    eps: float
    min_samples: int

    @property
    def n_clusters(self) -> int:
        return len({a.cluster for a in self.assignments if a.cluster != NOISE})

    @property
    def n_noise(self) -> int:
        return sum(1 for a in self.assignments if a.cluster == NOISE)


def _matrix(features: list) -> np.ndarray:
    matrix = np.array([f.vector() for f in features], dtype=float)
    if not np.isfinite(matrix).all():
        raise ValueError("Features contain non-finite values")
    return StandardScaler().fit_transform(matrix)


def suggest_eps(features: Iterable, min_samples: int = 5, percentile: float = 90.0) -> float:
    """eps = percentile des distances au min_samples-ième voisin. N'utilise aucun label."""
    features = list(features)
    if len(features) <= min_samples:
        raise ValueError("Not enough sessions to estimate eps")
    if not 0.0 < percentile <= 100.0:
        raise ValueError("percentile must be in ]0, 100]")
    scaled = _matrix(features)
    # n_neighbors = min_samples + 1 car chaque point est son propre voisin (distance 0)
    distances, _ = NearestNeighbors(n_neighbors=min_samples + 1).fit(scaled).kneighbors(scaled)
    eps = float(np.percentile(distances[:, -1], percentile))
    return max(eps, 1e-6)  # eps doit rester strictement positif


def cluster_sessions(
    features: Iterable,
    eps: Optional[float] = None,
    min_samples: int = 5,
) -> ClusteringResult:
    features = list(features)
    if min_samples < 2:
        raise ValueError("min_samples must be at least 2")
    if len(features) < MIN_SESSIONS:
        raise ValueError(f"At least {MIN_SESSIONS} sessions are required")
    if eps is None:
        eps = suggest_eps(features, min_samples)
    if eps <= 0:
        raise ValueError("eps must be positive")

    labels = DBSCAN(eps=eps, min_samples=min_samples).fit_predict(_matrix(features))
    assignments = tuple(
        ClusterAssignment(f.source, f.session_id, int(label))
        for f, label in zip(features, labels)
    )
    return ClusteringResult(assignments, float(eps), min_samples)


def cluster_report(result: ClusteringResult, labels: dict) -> list:
    """Composition de chaque cluster par rapport aux labels (0/1), pour interprétation.

    Retourne une liste de dicts triée par cluster : taille, attaques, part d'attaques.
    """
    groups = {}
    for a in result.assignments:
        key = (a.source, a.session_id)
        if key not in labels:
            raise ValueError("A clustered session has no label")
        groups.setdefault(a.cluster, []).append(labels[key])
    return [
        {
            "cluster": cluster,
            "size": len(values),
            "attacks": sum(values),
            "attack_share": sum(values) / len(values),
        }
        for cluster, values in sorted(groups.items())
    ]


def noise_sessions(result: ClusteringResult) -> set:
    return {(a.source, a.session_id) for a in result.assignments if a.cluster == NOISE}