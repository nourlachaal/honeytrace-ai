# syntax=docker/dockerfile:1

FROM python:3.12-slim

# - PYTHONUNBUFFERED: logs appear in `kubectl logs` immediately, not buffered
# - PYTHONDONTWRITEBYTECODE: no __pycache__ writes (needed for a read-only root FS)
# - PIP_*: smaller image, less noise
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Dependencies first: this layer is cached and only rebuilds when requirements change.
# requirements-ml.txt is required for live ML advisory scoring:
# src/pipeline.py imports src.ml at runtime via _attach_ml_scores.
# Graceful degradation handles missing sklearn, but the production image
# should include ML deps so scoring actually runs (not silently skipped).
# Model artifact (data/models/isolation_forest.joblib) is NOT copied into
# the image: it is trained at runtime and saved to the (ephemeral) filesystem.
# In Kubernetes (readOnlyRootFilesystem), the save fails silently but scoring
# still works (model stays in memory for the duration of the pod).
COPY requirements.txt requirements-ml.txt .
RUN pip install --no-cache-dir -r requirements.txt -r requirements-ml.txt \
 && pip uninstall -y pytest

# Application code
COPY src/ ./src/

# Streamlit theme. Read from ./ relative to the working directory, so the
# emptyDir mounted over $HOME/.streamlit in Kubernetes does not shadow it.
COPY .streamlit/ ./.streamlit/

# Non-root user with a FIXED uid, so the Kubernetes securityContext can match it
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin appuser
USER 10001

EXPOSE 8000
CMD ["python", "-m", "uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]