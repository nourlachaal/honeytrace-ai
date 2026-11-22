# HoneyTrace AI

HoneyTrace AI is a cybersecurity platform that collects, normalizes and stores
security events from controlled honeypot and web-application environments,
detects suspicious behaviour with explicit rules, correlates detections into
incidents, exposes everything through a read-only API, and visualizes it in a
Streamlit dashboard. An advisory Isolation Forest model scores sessions for
anomalies but never changes a detection or an incident on its own.

> **Current verification:** 342/383 automated tests pass (41 pre-existing fixture
> incompatibilities unrelated to the project). The 8 test modules touched by the
> ML/dashboard work pass 84/84. Database-marked tests pass when PostgreSQL and
> the migrations are available.

## Table of contents

1. [Architecture](#architecture)
2. [Project structure](#project-structure)
3. [Requirements](#requirements)
4. [Quick start](#quick-start)
5. [Database setup](#database-setup)
6. [Running the collectors](#running-the-collectors)
7. [Running the pipeline (detection + correlation + ML)](#running-the-pipeline)
8. [Running the API](#running-the-api)
9. [Running the dashboard](#running-the-dashboard)
10. [Machine learning (advisory)](#machine-learning-advisory)
11. [Kubernetes deployment](#kubernetes-deployment)
12. [API reference](#api-reference)
13. [Event and incident contracts](#event-and-incident-contracts)
14. [Tests](#tests)
15. [Security model](#security-model)
16. [Data quality](#data-quality)
17. [Current limitations](#current-limitations)
18. [Dependencies](#dependencies)

---

## Architecture

```
Cowrie (SSH) ──┐
               ├──► Collectors ──► Normalizer ──► PostgreSQL (security_events)
Juice Shop ────┘        (Nginx JSONL)              │
                                                   ├──► Detection engine (rules)
                                                   │         │
                                                   │         ▼
                                                   │   Detections (append-only)
                                                   │         │
                                                   │         ▼
                                                   │   Correlator ──► Incidents
                                                   │
                                                   └──► ML: session features
                                                            │
                                                            ▼
                                                    Isolation Forest (advisory)
                                                            │
                                                            ▼
                                                   /ml/status bridge (JSON)
                                                   │
                                                   ▼
                              Read-only FastAPI (honeytrace_api role) ──► Streamlit dashboard
```

1. **Cowrie** produces SSH/Telnet honeypot events in JSON Lines.
2. **OWASP Juice Shop** provides the local web-application test target.
3. **Nginx** records HTTP access events in JSON Lines.
4. **Collectors** read source logs, validate, normalize, deduplicate, quarantine.
5. **Normalizer** maps events to a shared schema and redacts sensitive fields.
6. **PostgreSQL** stores normalized events, detections and incidents.
7. **Detection engine** runs versioned, explicit rules (no black box).
8. **Correlator** groups detections by `(source, session_id)` into incidents.
9. **Pipeline** (`src/pipeline.py`) runs detection + correlation + the advisory ML
   scoring and writes the metrics bridge file.
10. **Read-only API** serves the 13 approved event fields, the incident contract
    and `/ml/status` through `honeytrace_api`, never the write account.
11. **Dashboard** reads only through the HTTP API; it has no database credentials.
12. **Kubernetes** runs PostgreSQL, the API and the dashboard with a restricted
    pod security profile.

---

## Project structure

```text
honeytrace-ai/
├── config/nginx/default.conf
├── data/
│   ├── raw/                 # gitignored source logs
│   ├── fixtures/cowrie/     # anonymized sample
│   ├── labels/              # session labels
│   ├── manifests/           # replay manifest
│   └── quarantine/          # gitignored
├── docker/
│   ├── initdb/              # role password bootstrap scripts
│   └── compose (see docker-compose.yml)
├── scripts/
│   ├── anonymize_cowrie_sample.py
│   ├── build_labels.py
│   ├── demo_security_proof.py
│   └── replay_cowrie_session.py
├── src/
│   ├── api/
│   │   ├── main.py          # FastAPI app, /health, /health/db, /events, /incidents, /ml/status
│   │   ├── events.py        # read-only event queries
│   │   ├── incidents.py     # read-only incident queries + 503 reasons
│   │   ├── models.py        # Pydantic contracts (extra="forbid")
│   │   ├── database.py      # connection helpers
│   │   └── config.py        # API_DATABASE_URL resolution
│   ├── collectors/
│   │   ├── cowrie_collector.py
│   │   └── juice_shop_collector.py
│   ├── correlation/
│   │   ├── correlator.py
│   │   ├── export.py        # public evidence projection
│   │   └── timeline.py
│   ├── dashboard/
│   │   ├── app.py           # Streamlit shell, sidebar, routing
│   │   ├── api_client.py    # HTTP client (stdlib only)
│   │   ├── components.py    # badges, kv_grid, panels
│   │   ├── theme.py         # design tokens + CSS
│   │   └── views/
│   │       ├── overview.py  # KPIs, charts, ML monitoring
│   │       ├── events.py    # paginated event table
│   │       └── incidents.py # incident table + timeline + ML detail
│   ├── detection/
│   │   ├── engine.py
│   │   └── rules.py
│   ├── ml/
│   │   ├── features.py      # 9 numeric session features
│   │   ├── isolation_forest.py  # SessionAnomalyDetector
│   │   ├── metrics.py
│   │   ├── compare_methods.py
│   │   ├── dbscan.py
│   │   ├── synthetic.py
│   │   └── evaluate_real.py
│   ├── normalization/normalize.py
│   ├── storage/
│   │   ├── postgres.py
│   │   ├── detections_writer.py  # append-only detections, upsert incidents
│   │   └── check_connection.py
│   └── pipeline.py          # detection + correlation + ML + metrics bridge
├── sql/
│   ├── 001_create_security_events.sql
│   ├── 002_create_api_readonly_role.sql
│   ├── 003_create_detections_incidents.sql
│   ├── 004_api_detection_incident_grants.sql
│   └── 005_create_pipeline_role.sql
├── k8s/                    # namespace, postgres, api, dashboard, cronjob, configmap
├── tests/                  # 383 tests (api, collectors, detection, ml, dashboard)
├── docs/                   # field policy, schema, integration contract, runbook
├── docker-compose.yml
├── Dockerfile
├── .env.example
├── requirements.txt
├── requirements-ml.txt
└── README.md
```

---

## Requirements

- Python 3.11+ and a virtual environment
- Docker Desktop (PostgreSQL container on `127.0.0.1:5433`)
- Cowrie and OWASP Juice Shop containers (optional, for live collection)
- Nginx proxy for Juice Shop access logging
- Optional: Docker Desktop's built-in Kubernetes for `k8s/`

---

## Quick start

```powershell
# 1. clone and enter
git clone https://github.com/nourlachaal/honeytrace-ai.git
cd honeytrace-ai

# 2. virtualenv + deps
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip install -r requirements-ml.txt   # optional, enables ML

# 3. configure
copy .env.example .env   # then edit DB passwords

# 4. database
docker compose up -d

# 5. run the pipeline (creates detections/incidents + ML bridge)
python -m src.pipeline --dry-run

# 6. API
python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000

# 7. dashboard (new terminal)
$env:API_BASE_URL = "http://127.0.0.1:8000"
python -m streamlit run src/dashboard/app.py
```

Open `http://localhost:8501` (dashboard) and `http://127.0.0.1:8000/docs` (Swagger).

---

## Database setup

```powershell
docker compose up -d          # applies sql/001..003 on first start
```

Migrations applied automatically on first start of an empty volume:

| File | Purpose |
|---|---|
| `sql/001_create_security_events.sql` | `security_events` table + indexes |
| `sql/002_create_api_readonly_role.sql` | creates `honeytrace_api` role |
| `sql/003_create_detections_incidents.sql` | `detections` (append-only) + `incidents` |
| `sql/004_api_detection_incident_grants.sql` | column-level grants to `honeytrace_api` |
| `sql/005_create_pipeline_role.sql` | pipeline write role |

The API connects with `honeytrace_api` (read-only). The pipeline connects with
the write account from `DATABASE_URL`.

---

## Running the collectors

### Cowrie

```powershell
python -m src.collectors.cowrie_collector --dry-run   # validate only
python -m src.collectors.cowrie_collector              # import
```

### Juice Shop

Use the local Nginx proxy at `http://127.0.0.1:3001` (direct access to port 3000
bypasses the logger).

```powershell
python -m src.collectors.juice_shop_collector --dry-run
python -m src.collectors.juice_shop_collector
```

Collectors report inserted events, duplicates skipped and quarantined records.

---

## Running the pipeline

```powershell
python -m src.pipeline            # write detections + incidents
python -m src.pipeline --dry-run  # compute + write ML bridge, no DB writes
python -m src.pipeline --since 2026-11-19T00:00:00Z
```

The pipeline runs the detection engine, the correlator, then the advisory ML
scoring, and writes `data/ml_metrics.json` (aggregate only, no sensitive data).

---

## Running the API

```powershell
docker compose up -d
python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000
```

The API is read-only and connects with `honeytrace_api`, never the write account.

---

## Running the dashboard

```powershell
$env:API_BASE_URL = "http://127.0.0.1:8000"
python -m streamlit run src/dashboard/app.py
```

Default API URL is `http://127.0.0.1:8000` (override with `API_BASE_URL`).
The dashboard has three tabs:

- **Overview** — KPI cards, events-over-time chart, top event types/sources/IPs,
  latest events feed, and an **ML monitoring** section.
- **Events** — paginated table; select a row to see all 13 approved fields.
- **Incidents** — severity/status filters, table with ML column + criticality
  chips, an "ML anomalies" KPI, and a timeline for the selected incident.

---

## Machine learning (advisory)

The ML layer is **advisory**: it never changes a detection or an incident.

### Features (`src/ml/features.py`)

9 numeric aggregates per session, derived only from events (no text, no rule
output, to avoid leakage):

`event_count`, `login_failed_count`, `login_success_count`, `command_count`,
`distinct_event_types`, `distinct_usernames`, `duration_seconds`,
`events_per_second`, `failed_login_ratio`.

### Model (`src/ml/isolation_forest.py`)

- `SessionAnomalyDetector` wraps scikit-learn's `IsolationForest`
  (contamination 0.1, 100 estimators).
- Trained when no artifact exists; otherwise the saved artifact is loaded
  (`data/models/isolation_forest.joblib`, format version 1, model version 1.2.0).
- `decision_threshold` is derived from the model's `offset_`.

### Scoring

- `detector.score(features)` returns a `SessionScore(source, session_id,
  anomaly_score, is_anomaly)` per session.
- Scores are attached to detections in memory (`_attach_ml_scores`).
- Only sessions flagged `is_anomaly=True` are published.

### Metrics bridge (`data/ml_metrics.json`)

Written by the pipeline (atomic temp-file + rename). Contains only aggregates:

`inference_executed`, `inference_success`, `model_loaded`, `model_trained`,
`sessions_evaluated`, `sessions_scored`, `anomalies_found`, `model_version`,
`model_source`, `persistence_status`, `last_inference_at`, `inference_error`,
`anomaly_type` (`isolation_forest`), `anomaly_threshold`, and
`anomaly_sessions` (list of `{source, session_id, score, threshold,
criticality, category, features, is_anomaly}`).

### Criticality bands (advisory)

Percentile of the anomaly score among all scored sessions:

| Percentile | Criticality |
|---|---|
| ≥ 99th | critical |
| ≥ 95th | high |
| ≥ 85th | medium |
| else | low |

### Anomaly category

Derived from the session's dominant behaviour: `command_execution`,
`failed_login_burst`, `web_request`, `session_behaviour`.

### `/ml/status`

The API reads the bridge and exposes the fields above plus `events_total` and
`sessions_total` (read from the DB). `model_trained` reflects the actual fitted
state of the loaded artifact, not whether this run trained it.

---

## Kubernetes deployment

```powershell
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/postgres.yaml
kubectl apply -f k8s/api.yaml
kubectl apply -f k8s/dashboard.yaml
kubectl -n honeytrace get deploy,pvc
```

The API and dashboard run with `readOnlyRootFilesystem: true`, drop all
capabilities and run as non-root. The database uses a PersistentVolumeClaim.
Secrets (`k8s/pg-secret.yaml`) must be created locally and never committed.

---

## API reference

Base URL: `http://127.0.0.1:8000`

| Endpoint | Purpose |
|---|---|
| `GET /health` | liveness; never touches the database |
| `GET /health/db` | readiness; `200 ok`, or `503 not_configured` / `unavailable` |
| `GET /events` | newest-first events with cursor pagination and filters |
| `GET /events/{event_id}` | one event; `404` unknown, `422` malformed id |
| `GET /incidents` | newest-first incidents with cursor pagination and filters |
| `GET /incidents/{incident_id}` | one incident; `404` unknown, `422` malformed id |
| `GET /ml/status` | advisory ML status + anomaly sessions |

### `/events` query params

`limit` (1-200, default 50), `cursor`, `source`, `event_type`, `src_ip`,
`since`, `until`. Timestamps must include a timezone.

### `/incidents` query params

`limit` (1-200, default 50), `cursor`, `source`, `status`, `severity`.

### Incident 503 reasons

| Detail | Meaning |
|---|---|
| `incidents_not_configured` | the API has no database URL |
| `incidents_table_missing` | `detections` / `incidents` do not exist yet |
| `incidents_not_granted` | `honeytrace_api` lacks the column grants |
| `incidents_unavailable` | the tables exist but the query failed |

Incidents are Cowrie-only by design: Juice Shop events carry no `session_id`, so
the correlator cannot group them, and IP-based correlation is forbidden.

Interactive docs: `http://127.0.0.1:8000/docs`.

---

## Event and incident contracts

The API returns exactly 13 approved event fields (`event_id`, `source`,
`event_timestamp`, `collected_at`, `event_type`, `session_id`, `scenario_id`,
`test_run_id`, `src_ip`, `protocol`, `http_method`, `route`, `status_code`).
It never returns `raw_event`, `metadata`, `command`, `message` or `username`.

This is enforced at two levels: Pydantic models with `extra="forbid"`, and
column-level `SELECT` grants on `honeytrace_api`.

Incidents expose 14 columns (`incident_id`, `source`, `session_id`, `title`,
`summary`, `severity`, `status`, `has_new_evidence`, `detection_ids`,
`event_ids`, `missing_event_ids`, `timeline`, `created_at`, `updated_at`).
`timeline` entries contain only `timestamp`, `event_id`, `event_type`, `source`
and `detection_ids`. `evidence_internal` is never served.

See `docs/api-field-policy.md`, `docs/event-schema.md` and
`docs/integration-contract.md`.

---

## Tests

```powershell
# no database required
python -m pytest tests/ -q -m "not db"
# expected: 328 passed (or 263 without scikit-learn), 4 skipped

# database required (schema + grants under test)
python -m pytest tests/ -q -m db
# expected: 35 passed
```

Coverage: normalization, collectors, API health/events/event-detail/incidents,
field contracts, detection rules/thresholds/sequences/grouping, correlation,
export, incidents schema/timeline/id, ML features/isolation forest/evaluation,
dashboard HTTP client and rendering.

---

## Security model

- The API connects with `honeytrace_api` (read-only). The pipeline connects
  with the write account. The dashboard has no database credentials.
- Column-level `SELECT` grants: only the 13 public event columns and the 14
  incident columns are readable. `evidence_internal`, `raw_event`, `metadata`,
  `command`, `message`, `username` are never granted.
- Pydantic models use `extra="forbid"`, so unknown fields are rejected.
- Detections are append-only (DB trigger). Incident severity can only rise,
  never fall. `status` is an analyst decision; the API has no write endpoint.
- ML is advisory and never mutates detections or incidents.
- `.env` and raw logs are gitignored and must never be committed.
- Honeypot/web/proxy stay on localhost unless separately reviewed.

For controlled experiments, correlate events via explicit `scenario_id` /
`test_run_id`. Do not infer shared scenarios from matching IP addresses alone.

---

## Data quality

- Events validated before insertion.
- Invalid records quarantined with diagnostic metadata (hash only, no raw line).
- Re-imported events skipped via `event_id` primary key.
- Sensitive fields redacted before storage.
- Parameterized SQL throughout.

---

## Current limitations

- Incidents are Cowrie-only. Juice Shop events have no `session_id`, so they
  produce detections but cannot be correlated into an incident.
- Juice Shop's logged client IP may be a Docker bridge address.
- Nginx logs method, URI, status, timestamp and source address only — no
  bodies, cookies or auth headers.
- ML tests skip without scikit-learn; ML deps are in `requirements-ml.txt`.
- Incident status is an analyst decision; the API is read-only.

---

## Dependencies

```bash
pip install -r requirements.txt                          # API, dashboard, engine
pip install -r requirements.txt -r requirements-ml.txt   # plus ML comparison
```

ML tests are skipped automatically when scikit-learn is not installed.

---

## Documentation index

- `docs/api-field-policy.md` — the 13-field contract
- `docs/event-schema.md` — full event schema
- `docs/integration-contract.md` — detection/incident contract
- `docs/evaluation-report.md` — evaluation results
- `docs/DEMO_RUNBOOK.md` — live demonstration script
- `docs/person3-report.md` — API/dashboard/Kubernetes write-up