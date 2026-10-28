
# HoneyTrace AI — Normalized Event Schema

## Purpose

HoneyTrace AI converts security events from Cowrie and OWASP Juice Shop into a consistent format for storage, detection, and dashboard use.

## Fields

| Field | Type | Description |
|---|---|---|
| event_id | string | SHA-256 identifier for deduplication |
| source | string | `cowrie` or `juice_shop` |
| source_event_id | string/null | Source-provided unique event identifier, if available |
| event_timestamp | UTC timestamp | Time the source recorded the event |
| collected_at | UTC timestamp | Time PostgreSQL received the event |
| event_type | string | Source-specific event type |
| session_id | string/null | Source session identifier |
| scenario_id | string/null | Explicit controlled-test scenario identifier |
| test_run_id | string/null | Explicit controlled-test run identifier |
| src_ip | string/null | Source IP address as reported by the source |
| protocol | string/null | Network protocol, such as SSH or HTTP |
| username | string/null | Username, when available |
| command | string/null | Command, when available |
| http_method | string/null | HTTP method, when available |
| route | string/null | HTTP route, when available |
| status_code | integer/null | HTTP response status, when available |
| message | string/null | Human-readable event description |
| metadata | JSON object | Additional sanitized fields |
| raw_event | JSON object | Sanitized source event, preserving its structure |

## Rules

1. Convert event timestamps to UTC.
2. Do not invent missing values.
3. Redact passwords, private credentials, and authentication key material before database insertion.
4. Preserve source-specific event details in sanitized metadata.
5. Generate a deterministic event ID so repeated imports can be deduplicated.
6. Populate scenario_id and test_run_id only from an explicit test manifest or mapping.
7. Treat source IP similarity alone as insufficient evidence that two events are related.
8. Quarantine malformed records and record the reason without copying secrets into error messages.
9. Never commit credentials, environment files, or raw security logs to Git.
