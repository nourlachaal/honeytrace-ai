## Person 1: data collection, lab scenarios, labels and database

This part collects security events from two controlled sources, normalizes them
into one schema, stores them in PostgreSQL and produces labeled sessions for the
detection work.

### Lab sources (local only, bound to 127.0.0.1)

| Source | Container | Port | Output |
|---|---|---|---|
| Cowrie SSH/Telnet honeypot | `honeytrace-cowrie` | 2222 / 2223 | `data/raw/cowrie/cowrie-var/log/cowrie/cowrie.json` |
| OWASP Juice Shop | `honeytrace-juice-shop` | 3000 | none (see proxy) |
| Nginx logging proxy for Juice Shop | `honeytrace-juice-proxy` | 3001 | `data/raw/juice-shop/access.jsonl` |

Send browser requests through `http://127.0.0.1:3001` so they are logged.

Cowrie pitfall: mounting an empty host folder over `/cowrie/cowrie-git/var` hides
the folders the image ships. Create them before starting Cowrie, otherwise
shells fail with `FileNotFoundError` and no commands are recorded:

```powershell
New-Item -ItemType Directory -Force data\raw\cowrie\cowrie-var\lib\cowrie\tty
New-Item -ItemType Directory -Force data\raw\cowrie\cowrie-var\lib\cowrie\downloads
New-Item -ItemType Directory -Force data\raw\cowrie\cowrie-var\run
```

Pipeline & Event Identity
Collectors (src/collectors/) read the logs (including rotated cowrie.json.*
files), src/normalization/normalize.py maps them to the shared security_events
schema (UTC timestamps, key-based secret redaction, stable SHA-256 event_id), and
src/storage/postgres.py inserts them with ON CONFLICT DO NOTHING using the
least-privilege honeytrace_collector role. Malformed records go to quarantine
with diagnostic metadata only. Real Cowrie commands arrive in the raw field
input and are mapped to the command column.

Both collectors accept --scenario-id and --test-run-id parameters. These run
tags are excluded from the event_id hash so re-importing labeled runs does not
create duplicate events. For Juice Shop, Nginx emits a per-request $request_id
in access.jsonl so identical HTTP requests within the same second produce
distinct event_id hashes.
```powershell
python -m src.collectors.cowrie_collector --dry-run
python -m src.collectors.cowrie_collector
python -m src.collectors.juice_shop_collector
```

### Scripted scenarios and labels

`scripts/replay_cowrie_session.py` replays harmless, scripted sessions against the
local honeypot (it refuses any host except 127.0.0.1) and records every run in
`data/manifests/replay_manifest.csv`. Four scenarios: `normal-basic`,
`normal-admin` (label 0), `attack-basic`, `attack-recon` (label 1).

```powershell
python scripts/replay_cowrie_session.py --scenario attack-basic --test-run-id RUN-2026-11-16-002
python -m src.collectors.cowrie_collector
python scripts/build_labels.py
```

scripts/build_labels.py matches each completed run to its Cowrie session by
start time and writes data/labels/session_labels.csv
(source,session_id,label,scenario_id,test_run_id). Runs that match zero or
several sessions are skipped, never guessed. Current set: 23 labeled sessions
(11 normal, 12 attack-like across RUN-2026-11-16-001 and RUN-2026-11-16-002),
with raw events exported in data/raw/labeled_cowrie_runs.jsonl and tagged in
PostgreSQL. Sessions without a manifest entry are unlabeled and must not be used
for evaluation.

scripts/anonymize_cowrie_sample.py produces the shareable sample
data/fixtures/cowrie/sample_anonymized.jsonl (IPs replaced by 203.0.113.x,
session ids hashed, credentials removed).
### Database migrations

| File | Purpose |
|---|---|
| `sql/001_create_security_events.sql` | normalized events (source of truth) |
| `sql/002_create_api_readonly_role.sql` | read-only API role (Person 3) |
| `sql/003_create_detections_incidents.sql` | `detections` and `incidents` tables |
| `sql/004_api_detection_incident_grants.sql` | column-level grants for the API role |

`003` enforces the contract in the database: `incident_id` must equal
SHA-256 of `incident|<source>|<session_id>`, `|` is rejected in both parts,
`evidence_public` rejects `username`, `command` and similar keys, severity can
only rise, and detections are append-only. `004` grants column-level `SELECT`
only; the API cannot read `evidence_internal` or `missing_event_ids`.

On an existing database apply the files manually, in order (init scripts only
run on an empty volume):

```powershell
Get-Content sql/003_create_detections_incidents.sql -Raw | docker exec -i projet-cyber-postgres-1 psql -U hive -d honeytrace -v ON_ERROR_STOP=1
Get-Content sql/004_api_detection_incident_grants.sql -Raw | docker exec -i projet-cyber-postgres-1 psql -U hive -d honeytrace -v ON_ERROR_STOP=1
```

Status and known limitations
Tests: 317 passed, 21 skipped (all 36 database permission and schema tests pass when API_DATABASE_URL is set).

All lab sessions share one source IP (the Docker gateway), so IP-based features are meaningless on this data.

Sessions are scripted, so detection metrics will look optimistic compared to real traffic.

Juice Shop events have no session_id, so they produce detections but no incidents.

Never commit .env, raw unexported logs, or quarantine files.
'@