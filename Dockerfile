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

# Dependencies first: this layer is cached and only rebuilds when requirements.txt changes
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && pip uninstall -y pytest

# Application code
COPY src/ ./src/

# Non-root user with a FIXED uid, so the Kubernetes securityContext can match it
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin appuser
USER 10001

EXPOSE 8000
CMD ["python", "-m", "uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]