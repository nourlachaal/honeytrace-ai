# HoneyTrace AI — Person 1 Handoff

## 1. My role

I am Person 1, responsible for collecting security logs from Cowrie and OWASP Juice Shop, normalizing the events into a shared schema, and storing them in PostgreSQL for the rest of the HoneyTrace AI team.

## 2. Project environment

- **Operating system:** Windows, using PowerShell and VS Code
- **Python:** 3.14.0
- **Environment:** Python virtual environment (`.venv`)
- **Container platform:** Docker Desktop
- **Database:** PostgreSQL 17.11 running in Docker
- **Database name:** `honeytrace`
- **Database user:** `hive`
- **Database port:** `5433` on localhost
- **Honeypot:** Cowrie Docker image downloaded successfully

## 3. Work completed

### Python environment

- Created the project directory and initial folder structure.
- Created and activated `.venv`.
- Installed the project dependencies:
  - `psycopg[binary]`
  - `python-dotenv`
  - `pytest`
- Verified that the Python dependencies import successfully.

### PostgreSQL setup

- Reused the existing PostgreSQL Docker container named `projet-cyber-postgres-1`.
- Started the container and verified that port `5433` is reachable locally.
- Created the `honeytrace` database without creating a duplicate PostgreSQL server.
- Created `src/storage/test_connection.py`.
- Successfully connected from Python to the `honeytrace` database.
- Created `sql/001_create_security_events.sql`.
- Applied the SQL schema and verified that the `security_events` table and its indexes exist.

### Database event schema

The shared table includes:

- Event ID and source
- Original source event ID
- Event timestamp and collection timestamp
- Event type and session ID
- Scenario ID and test-run ID
- Source IP and protocol
- Username and command
- HTTP method, route and status code
- Message, metadata and raw event JSON

The table supports events from both Cowrie and Juice Shop. Optional fields can remain `NULL` when a source does not provide the information.

### Cowrie setup

- Downloaded the official `cowrie/cowrie:latest` Docker image.
- Attempted to inspect the image using `sh`, but the image did not provide that executable in its PATH.
- Cowrie has **not yet been started or tested**, and its log path still needs to be verified.

## 4. Current project structure

```text
honeytrace-ai/
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
│       └── test_connection.py
├── sql/
│   └── 001_create_security_events.sql
├── tests/
├── docs/
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

Some listed files and folders may still be empty or need verification.

## 5. Remaining tasks for Person 1

1. Start Cowrie with its service port bound only to `127.0.0.1`.
2. Verify the actual Cowrie JSON log location.
3. Implement `cowrie_collector.py` to read Cowrie events.
4. Implement and test event normalization.
5. Implement PostgreSQL insertion with parameterized queries and duplicate-event handling.
6. Implement `juice_shop_collector.py` after verifying the application's actual log format.
7. Add sanitized test fixtures and unit tests.
8. Quarantine malformed events with an error reason instead of silently discarding them.
9. Redact passwords, tokens, cookies and other secrets before storing events.
10. Document the schema and ingestion instructions for teammates.
11. Test end-to-end ingestion and share the schema with Persons 2 and 3.

## 6. Team integration

- **Person 1:** Collect, normalize and store source events.
- **Person 2:** Develop detection logic and machine-learning features using normalized events.
- **Person 3:** Build the API and dashboard.

The team should use `scenario_id` and `test_run_id` for controlled test correlation. Source session IDs are not necessarily shared between Cowrie and Juice Shop, and an IP address alone is not proof that two events belong to the same activity.

## 7. Security and repository rules

- Never commit `.env`, passwords, tokens or other secrets.
- Keep raw logs and quarantined records out of Git unless a specific, sanitized fixture is intentionally selected.
- Commit sanitized fixtures for reproducible tests.
- Keep honeypot services restricted to localhost during development.
- Use parameterized SQL queries.
- Do not claim that collectors or end-to-end ingestion work until they have been implemented and tested.

## 8. Current status

**Completed:** Python environment, PostgreSQL connectivity, database creation, event table creation, and Cowrie image download.

**In progress:** Cowrie deployment, log discovery, collectors, normalization, storage integration, and automated tests.
