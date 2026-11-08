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

**Current verification:** 37 automated tests pass. The latest database verification showed 10 Cowrie events and 80 Juice Shop events.

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
│   ├── collectors/
│   │   ├── cowrie_collector.py
│   │   └── juice_shop_collector.py
│   ├── normalization/
│   │   └── normalize.py
│   └── storage/
│       ├── postgres.py
│       └── check_connection.py
├── sql/
│   └── 001_create_security_events.sql
├── tests/
│   ├── test_cowrie_collector.py
│   ├── test_juice_shop_collector.py
│   └── test_normalize.py
├── docs/
│   └── event-schema.md
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

## Running Tests

Run the full test suite:

```powershell
python -m pytest tests/ -q
```

The current suite contains 37 passing tests covering normalization, Juice Shop collector behavior, and the API health, events, and event-detail endpoints.

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
