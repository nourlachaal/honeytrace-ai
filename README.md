# HoneyTrace AI

HoneyTrace AI is a cybersecurity project that collects, normalizes, and stores security events from controlled honeypot and web-application environments. The goal is to provide a consistent dataset for later detection, correlation, and dashboard development.

## Project Status

The initial data collection and storage pipeline is implemented and tested.

- Cowrie SSH honeypot event collection
- OWASP Juice Shop HTTP access logging through Nginx
- Shared event normalization
- Sensitive-field redaction
- PostgreSQL persistence
- Duplicate-event handling
- Quarantine records for invalid input
- Automated tests for normalization and Juice Shop collection

**Current verification:** 47 automated tests pass. The latest database verification showed 10 Cowrie events and 80 Juice Shop events. The latest database verification showed 10 Cowrie events and 80 Juice Shop events.

## Architecture

1. **Cowrie:** produces SSH/Telnet honeypot events in JSON Lines format.
2. **OWASP Juice Shop:** provides the local web-application test environment.
3. **Nginx:** records HTTP access events in JSON Lines format.
4. **Collectors:** read source logs, validate events, and call the normalizer.
5. **Normalizer:** maps events into a shared schema and redacts sensitive fields.
6. **PostgreSQL:** stores normalized events for later querying and analysis.
7. **Future integration:** detection logic and an API/dashboard can consume the shared event schema.

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
├── src/
│   ├── api/
│   │   ├── main.py
│   │   ├── events.py
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
├── tests/
│   ├── test_api_events.py
│   ├── test_api_event_detail.py
│   ├── test_api_health.py
│   ├── test_api_health_db.py
│   ├── test_cowrie_collector.py
│   ├── test_dashboard_app.py
│   ├── test_dashboard_client.py
│   ├── test_juice_shop_collector.py
│   └── test_normalize.py
├── docs/
│   ├── api-field-policy.md
│   └── event-schema.md
├── docker-compose.yml
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

`GET /events` accepts `limit` (1-200, default 50), `cursor`, `source`, `event_type`,
`src_ip`, `since`, and `until`. Timestamps must include a timezone. Interactive
documentation is available at `http://127.0.0.1:8000/docs`.

The API returns exactly 13 approved fields. See `docs/api-field-policy.md`.

## Running the Dashboard

```powershell
python -m streamlit run src/dashboard/app.py
```

The dashboard reads only through the HTTP API (default `http://127.0.0.1:8000`,
override with `API_BASE_URL`). It never connects to PostgreSQL directly, so the
field allowlist and the column-level grants remain the only access path.

## Running Tests

Run the full test suite:

```powershell
python -m pytest tests/ -q
```

The current suite contains 47 passing tests covering normalization, collector behavior, the API health, events and event-detail endpoints, and the dashboard's HTTP client and rendering.

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

- The initial pipeline collects and stores events; it does not yet represent the complete detection and dashboard system.
- Juice Shop's logged client IP may be a Docker bridge address rather than the original browser address.
- The Nginx configuration logs the request method, URI path, status code, timestamp, and source address. It does not capture request bodies, cookies, or authorization headers.
- Correlation, detection rules or models, and API/dashboard integration require further development by the team.

## Next Steps

1. Expand tests for duplicate imports, invalid timestamps, and sensitive-field redaction.
2. Complete and review the event schema documentation.
3. Review Git changes to ensure no secrets or raw logs are staged.
4. Integrate the schema with the detection and API/dashboard components.
5. Test the complete pipeline using controlled, documented test runs.


## Dependencies

- `requirements.txt`: API, dashboard and the detection/correlation engine.
- `requirements-ml.txt`: only for `src/ml/` (Isolation Forest, DBSCAN, comparison).

```bash
pip install -r requirements.txt                          # API, dashboard, engine
pip install -r requirements.txt -r requirements-ml.txt   # plus the ML comparison
```

ML tests are skipped automatically when scikit-learn is not installed.