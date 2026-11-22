"""Détection d'anomalies par Isolation Forest sur les features de session.

Non supervisé : les labels ne sont jamais utilisés ici.
Une anomalie n'est PAS une attaque confirmée.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

# ML-specific versions (independent from detection engine DETECTOR_VERSION).
MODEL_VERSION = "1.2.0"
ARTIFACT_FORMAT_VERSION = "1"
SUPPORTED_ARTIFACT_FORMAT_VERSIONS = {"1", "legacy"}

MIN_SESSIONS = 20
DEFAULT_SAVE_RETRIES = 3
DEFAULT_SAVE_RETRY_DELAY = 0.1


@dataclass(frozen=True)
class SessionScore:
    source: str
    session_id: str
    anomaly_score: float   # plus élevé = plus inhabituel
    is_anomaly: bool       # signal à investiguer, pas une preuve d'attaque


class SessionAnomalyDetector:
    def __init__(self, contamination: float = 0.1, n_estimators: int = 100,
                 random_state: int = 42, version: str = MODEL_VERSION):
        if not 0.0 < contamination <= 0.5:
            raise ValueError("contamination must be in ]0, 0.5]")
        if n_estimators < 1:
            raise ValueError("n_estimators must be positive")
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        # Model version (not detector/engine version).
        self.version = version
        self.model_version = version
        self._scaler = None
        self._model = None

    @property
    def is_fitted(self) -> bool:
        return self._model is not None

    @property
    def decision_threshold(self) -> float | None:
        """Anomaly-score value above which the model predicts -1 (anomaly).

        ``score()`` returns ``-score_samples``, while sklearn predicts -1 when
        ``score_samples < offset_``. So the equivalent threshold on the score
        is ``-offset_``. Returns None when the detector is not fitted.
        """
        if not self.is_fitted:
            return None
        offset = getattr(self._model, "offset_", None)
        if offset is None:
            return None
        try:
            return -float(offset)
        except (TypeError, ValueError):
            try:
                return -float(offset[0])
            except (TypeError, IndexError, ValueError):
                return None

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

    def save(self, path, retries: int = DEFAULT_SAVE_RETRIES,
             retry_delay: float = DEFAULT_SAVE_RETRY_DELAY) -> str:
        """Persist the fitted detector to a versioned joblib artifact.

        Creates missing parent directories safely. Retries transient filesystem
        errors (OSError) a bounded number of times. Verifies the saved artifact
        can be loaded. Returns the artifact format version saved.
        Raises on persistent failure (never silently ignored by this method).
        """
        if not self.is_fitted:
            raise RuntimeError("Cannot save an unfitted detector")
        import joblib

        p = Path(path)
        payload = {
            "artifact_format_version": ARTIFACT_FORMAT_VERSION,
            "model_version": self.model_version,
            "detector": self,
        }
        last_exc = None
        attempts = max(1, int(retries))
        for attempt in range(1, attempts + 1):
            try:
                p.parent.mkdir(parents=True, exist_ok=True)
                # Write to a temp file in same directory then replace for safety.
                tmp = p.with_suffix(p.suffix + ".tmp")
                joblib.dump(payload, tmp)
                tmp.replace(p)
                # Verify saved artifact can be loaded.
                SessionAnomalyDetector.load(p, expected_model_version=self.model_version)
                logger.info("ML artifact saved: path=%s model_version=%s format=%s attempt=%s",
                            p, self.model_version, ARTIFACT_FORMAT_VERSION, attempt)
                return ARTIFACT_FORMAT_VERSION
            except OSError as exc:
                last_exc = exc
                logger.warning("ML artifact save attempt %s/%s failed (path=%s): %s",
                               attempt, attempts, p, exc)
                try:
                    tmp_path = p.with_suffix(p.suffix + ".tmp")
                    if tmp_path.exists():
                        tmp_path.unlink()
                except OSError:
                    pass
                if attempt < attempts:
                    time.sleep(retry_delay * attempt)
            except Exception:
                # Non-transient / verification failure: do not retry blindly.
                raise
        raise OSError(f"Failed to save ML artifact after {attempts} attempts: {last_exc}") from last_exc

    @staticmethod
    def load(path, expected_model_version: str | None = None) -> "SessionAnomalyDetector":
        """Load a fitted detector from a joblib artifact.

        Supports the current envelope format and legacy raw-detector artifacts.
        Raises FileNotFoundError if missing. Raises ValueError if corrupt,
        incompatible, or invalid.
        """
        import joblib

        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Model artifact not found: {p}")

        try:
            obj = joblib.load(p)
        except (EOFError, KeyError, ValueError, OSError, ImportError, ModuleNotFoundError, TypeError) as exc:
            raise ValueError(f"Corrupt or unreadable ML artifact: {p} ({exc})") from exc
        except Exception as exc:
            # joblib/pickle can raise various exceptions for corrupted data.
            raise ValueError(f"Corrupt or unreadable ML artifact: {p} ({exc})") from exc

        artifact_format = "legacy"
        detector = obj
        artifact_model_version = None

        if isinstance(obj, dict) and "detector" in obj:
            artifact_format = str(obj.get("artifact_format_version", ""))
            artifact_model_version = obj.get("model_version")
            detector = obj.get("detector")
            if artifact_format not in SUPPORTED_ARTIFACT_FORMAT_VERSIONS:
                raise ValueError(
                    f"Incompatible artifact format version '{artifact_format}' in {p}"
                )
        elif isinstance(obj, SessionAnomalyDetector):
            artifact_format = "legacy"
            artifact_model_version = getattr(obj, "version", None)
            detector = obj
        else:
            raise ValueError(f"Invalid ML artifact content in {p}: {type(obj)!r}")

        if not isinstance(detector, SessionAnomalyDetector) or not detector.is_fitted:
            raise ValueError(f"Invalid or unfitted detector artifact: {p}")

        # Normalize attributes for legacy artifacts.
        if not hasattr(detector, "model_version"):
            detector.model_version = getattr(detector, "version", artifact_model_version)
        if artifact_model_version is not None:
            detector.model_version = str(artifact_model_version)

        if expected_model_version is not None and str(detector.model_version) != str(expected_model_version):
            raise ValueError(
                f"Incompatible model version in {p}: found {detector.model_version}, "
                f"expected {expected_model_version}"
            )

        # Track the artifact format observed at load time for reporting.
        detector.artifact_format_version = artifact_format
        logger.info("ML artifact loaded: path=%s model_version=%s format=%s",
                    p, detector.model_version, artifact_format)
        return detector
