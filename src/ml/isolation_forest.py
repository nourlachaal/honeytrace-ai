"""Détection d'anomalies par Isolation Forest sur les features de session.

Non supervisé : les labels ne sont jamais utilisés ici.
Une anomalie n'est PAS une attaque confirmée.
"""

from dataclasses import dataclass
from typing import Iterable

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

MIN_SESSIONS = 20


@dataclass(frozen=True)
class SessionScore:
    source: str
    session_id: str
    anomaly_score: float   # plus élevé = plus inhabituel
    is_anomaly: bool       # signal à investiguer, pas une preuve d'attaque


class SessionAnomalyDetector:
    def __init__(self, contamination: float = 0.1, n_estimators: int = 100,
                 random_state: int = 42):
        if not 0.0 < contamination <= 0.5:
            raise ValueError("contamination must be in ]0, 0.5]")
        if n_estimators < 1:
            raise ValueError("n_estimators must be positive")
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self._scaler = None
        self._model = None

    @property
    def is_fitted(self) -> bool:
        return self._model is not None

    @staticmethod
    def _matrix(features: list) -> np.ndarray:
        matrix = np.array([f.vector() for f in features], dtype=float)
        if not np.isfinite(matrix).all():
            raise ValueError("Features contain non-finite values")
        return matrix

    def fit(self, features: Iterable) -> "SessionAnomalyDetector":
        features = list(features)
        if len(features) < MIN_SESSIONS:
            raise ValueError(f"At least {MIN_SESSIONS} sessions are required")
        matrix = self._matrix(features)
        self._scaler = StandardScaler().fit(matrix)
        self._model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
        ).fit(self._scaler.transform(matrix))
        return self

    def score(self, features: Iterable) -> list:
        if not self.is_fitted:
            raise RuntimeError("Model is not fitted")
        features = list(features)
        if not features:
            return []
        scaled = self._scaler.transform(self._matrix(features))
        scores = -self._model.score_samples(scaled)
        flags = self._model.predict(scaled) == -1
        return [
            SessionScore(f.source, f.session_id, float(s), bool(flag))
            for f, s, flag in zip(features, scores, flags)
        ]