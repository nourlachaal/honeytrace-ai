# HoneyTrace AI

HoneyTrace AI is a cybersecurity project that collects, normalizes, and stores security events from controlled honeypot and web-application environments. The goal is to provide a consistent dataset for later detection, correlation, and dashboard development.

## Project Status

The collection, storage, read-only API and dashboard are implemented and tested.

- Cowrie SSH honeypot event collection
- OWASP Juice Shop HTTP access logging through Nginx
- Shared event normalization
- Sensitive-field redaction
- PostgreSQL persistence
- Duplicate-event handling
- Quarantine records for invalid input
- Read-only FastAPI service using the dedicated `honeytrace_api` role
- Streamlit dashboard with Overview, Events and Incidents tabs
- Incident API over the detection/correlation tables, with typed 503 reasons
- Kubernetes manifests for PostgreSQL, the API and the dashboard

**Current verification:** 91 automated tests pass with `-m "not db"`; 35 additional
database-marked tests run when PostgreSQL and the migrations are available. The
dashboard and API are exercised against the HTTP contract, so the suite does not
need a live database to catch field leaks or broken rendering.

## Architecture

1. **Cowrie:** produces SSH/Telnet honeypot events in JSON Lines format.
2. **OWASP Juice Shop:** provides the local web-application test environment.
3. **Nginx:** records HTTP access events in JSON Lines format.
4. **Collectors:** read source logs, validate events, and call the normalizer.
5. **Normalizer:** maps events into a shared schema and redacts sensitive fields.
6. **PostgreSQL:** stores normalized events, detections and incidents.
7. **Detection and correlation:** rules and the correlator group evidence by
   `(source, session_id)` and write incidents.
8. **Read-only API:** serves 13 approved event fields and the incident contract
   through `honeytrace_api`, never the write account.
9. **Dashboard:** reads only through the HTTP API and renders events and
   incidents; it has no database credentials.
10. **Kubernetes:** runs PostgreSQL, the API and the dashboard with a restricted
    pod security profile and a `readOnlyRootFilesystem` for the stateless pods.

## Project Structure

```text
honeytrace-ai/
├── config/
│   └── nginx/
│       └── default.conf
├── data/
│   ├── raw/
│   │   ├── cowrie/
│   │   └── juice-shop/
│   ├── fixtures/
│   │   ├── cowrie/
│   │   └── juice-shop/
│   └── quarantine/
├── docker/
│   └── initdb/
│       └── 003_set_api_role_password.sh
├── src/
│   ├── api/
│   │   ├── main.py
│   │   ├── events.py
│   │   ├── incidents.py
│   │   ├── models.py
│   │   ├── database.py
│   │   └── config.py
│   ├── collectors/
│   │   ├── cowrie_collector.py
│   │   └── juice_shop_collector.py
│   ├── dashboard/
│   │   ├── app.py
│   │   └── api_client.py
│   ├── normalization/
│   │   └── normalize.py
│   └── storage/
│       ├── postgres.py
│       └── check_connection.py
├── sql/
│   ├── 001_create_security_events.sql
│   └── 002_create_api_readonly_role.sql
├── k8s/
│   ├── namespace.yaml
│   ├── postgres.yaml
│   ├── api.yaml
│   └── dashboard.yaml
├── tests/
│   ├── test_api_db_permissions.py
│   ├── test_api_event_detail.py
│   ├── test_api_events.py
│   ├── test_api_field_contract.py
│   ├── test_api_health.py
│   ├── test_api_health_db.py
│   ├── test_cowrie_collector.py
│   ├── test_dashboard_app.py
│   ├── test_dashboard_client.py
│   ├── test_incident_field_contract.py
│   ├── test_incident_schema.py
│   ├── test_juice_shop_collector.py
│   └── test_normalize.py
├── docs/
│   ├── api-field-policy.md
│   └── event-schema.md
├── docker-compose.yml
├── Dockerfile
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

## Requirements

- Python and a virtual environment
- Docker Desktop
- PostgreSQL
- Cowrie and OWASP Juice Shop containers
- Nginx proxy for Juice Shop access logging
- Optional: Docker Desktop's built-in Kubernetes for the manifests in `k8s/`

## Python Setup

From the project root, activate the virtual environment in PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

Configure the database connection in a local `.env` file using the variable documented in `.env.example`. Do not commit `.env` or real credentials.

The PostgreSQL database and the `security_events` table must be available before importing events. The schema is defined in `sql/001_create_security_events.sql`.

## Running the Collectors

### Cowrie

Run a dry run to validate and normalize the current log without inserting records:

```powershell
python -m src.collectors.cowrie_collector --dry-run
```

Import events into PostgreSQL:

```powershell
python -m src.collectors.cowrie_collector
```

### Juice Shop

Use the local Nginx proxy at `http://127.0.0.1:3001` to generate requests that should be logged. Direct access to the application on port 3000 bypasses the proxy logger.

Validate and normalize the access log:

```powershell
python -m src.collectors.juice_shop_collector --dry-run
```

Import events into PostgreSQL:

```powershell
python -m src.collectors.juice_shop_collector
```

The collectors report inserted events, duplicate events skipped, and quarantined records.

## Running the API

The API is read-only and connects with the dedicated `honeytrace_api` role, never
the collector's write account.

```powershell
docker compose up -d
python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000
```

| Endpoint | Purpose |
|---|---|
| `GET /health` | liveness; never touches the database |
| `GET /health/db` | readiness; `200 ok`, or `503 not_configured` / `unavailable` |
| `GET /events` | newest-first events with cursor pagination and filters |
| `GET /events/{event_id}` | one event; `404` unknown, `422` malformed id |
| `GET /incidents` | newest-first incidents with cursor pagination and filters |
| `GET /incidents/{incident_id}` | one incident; `404` unknown, `422` malformed id |

`GET /events` accepts `limit` (1-200, default 50), `cursor`, `source`, `event_type`,
`src_ip`, `since`, and `until`. Timestamps must include a timezone. Interactive
documentation is available at `http://127.0.0.1:8000/docs`.

The API returns exactly 13 approved event fields. See `docs/api-field-policy.md`.

`GET /incidents` accepts `limit` (1-200, default 50), `cursor`, `source`, `status`
and `severity`. It serves 14 incident columns and never serves `evidence_internal`
or any raw evidence. `timeline` entries are typed and may contain only
`timestamp`, `event_id`, `event_type`, `source` and `detection_ids`.

Until the incident tables exist, the endpoint answers `503` with a machine-readable
reason instead of failing:

| Detail | Meaning |
|---|---|
| `incidents_not_configured` | the API has no database URL |
| `incidents_table_missing` | `detections` / `incidents` do not exist yet |
| `incidents_not_granted` | `honeytrace_api` lacks the column grants |
| `incidents_unavailable` | the tables exist but the query failed |

Incidents are Cowrie-only by design: Juice Shop events carry no `session_id`, so
the correlator cannot group them, and IP-based correlation is forbidden.

## Running the Dashboard

```powershell
python -m streamlit run src/dashboard/app.py
```

The dashboard reads only through the HTTP API (default `http://127.0.0.1:8000`,
override with `API_BASE_URL`). It never connects to PostgreSQL directly, so the
field allowlist and the column-level grants remain the only access path.

It has three tabs:

- **Overview** — KPI cards, an events-over-time chart, top event types, sources
  and source IPs, and the latest events.
- **Events** — the paginated event table; select a row to see all 13 approved
  fields.
- **Incidents** — severity/status filters, a table of incidents with a
  "new evidence" badge, and a timeline for the selected incident. When the
  incident tables are missing, the tab explains the exact API reason instead of
  failing.

## Kubernetes Deployment

The manifests in `k8s/` run PostgreSQL, the API and the dashboard in the
`honeytrace` namespace. The database password and the API role password come from
one Secret; no credential is stored in a manifest.

```powershell
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/postgres.yaml
kubectl apply -f k8s/api.yaml
kubectl apply -f k8s/dashboard.yaml
kubectl -n honeytrace get deploy,pvc
```

The API and dashboard run with `readOnlyRootFilesystem: true`, drop all
capabilities and run as non-root. The database uses a PersistentVolumeClaim so
events survive a pod restart.

## Running Tests

Run the suite that needs no database:

```powershell
python -m pytest tests/ -q -m "not db"
```

Expected: `91 passed`. These tests cover normalization, collector behavior, the
API health, events and event-detail endpoints, the incident field contract, and
the dashboard's HTTP client and rendering.

Database-marked tests check the real schema and grants. They require PostgreSQL
with `sql/001` and `sql/002` applied, plus the incident migrations when present:

```powershell
python -m pytest tests/ -q -m db
```

Expected: `35 passed` once the tables and grants exist. Without a reachable
database they skip; with a database but missing tables, the incident acceptance
tests fail on purpose, because the schema is the thing under test.

## Event Storage

Normalized events are stored in the PostgreSQL `security_events` table.

Important fields include:

- `event_id`: stable SHA-256 identifier used to deduplicate events
- `source`: event source, such as `cowrie` or `juice_shop`
- `event_timestamp`: source event timestamp with timezone
- `event_type`: type of event
- `session_id`: source session identifier when available
- `scenario_id` and `test_run_id`: optional identifiers for controlled test correlation
- `src_ip`, `protocol`, `username`, and `command`: source-specific details when available
- `http_method`, `route`, and `status_code`: HTTP request details when available
- `metadata`: additional structured information
- `raw_event`: sanitized source event

See `docs/event-schema.md` for the detailed schema.

The detection and correlation stages write two further tables, `detections` and
`incidents`, which the incident API reads through column-level grants. Their
migrations are owned by the data-pipeline workstream and are not yet in this
repository; until they land, `GET /incidents` answers
`503 incidents_table_missing` and the dashboard shows that reason.

## Data Quality and Security

- Events are validated before insertion.
- Invalid records are quarantined with diagnostic metadata.
- Re-imported events are skipped using the `event_id` primary key.
- Sensitive fields are redacted before normalized events are stored.
- Database writes use parameterized SQL.
- Local raw logs may contain sensitive information and must not be committed.
- `.env` must remain local and must never be committed.
- Keep the honeypot, web application, and proxy restricted to localhost unless a separately reviewed deployment plan requires otherwise.

For controlled experiments, use explicit `scenario_id` or `test_run_id` mappings when correlating events across sources. Do not infer that events belong to the same scenario from matching IP addresses alone.

## Current Limitations

- The incident tables (`detections`, `incidents`) and the persistence writer are
  not in this repository yet, so the incident API is implemented and tested but
  not yet populated with real data.
- Incidents are Cowrie-only. Juice Shop events have no `session_id`, so they
  produce detections but cannot be correlated into an incident. IP-based
  correlation is deliberately not used.
- Juice Shop's logged client IP may be a Docker bridge address rather than the original browser address.
- The Nginx configuration logs the request method, URI path, status code, timestamp, and source address. It does not capture request bodies, cookies, or authorization headers.
- The ML comparison runs offline and is not part of the API or dashboard image.
- Incident status is an analyst decision; the API is read-only and does not
  expose a write endpoint.

## Next Steps

1. Land the `detections` and `incidents` migrations and the persistence writer,
   then run the engine end to end on real Cowrie data.
2. Expand tests for duplicate imports, invalid timestamps, and sensitive-field redaction.
3. Complete and review the event schema documentation.
4. Review Git changes to ensure no secrets or raw logs are staged.
5. Run the complete pipeline against controlled, documented test runs and record
   the evidence in the evaluation report.
