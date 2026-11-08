# HoneyTrace AI — API Field Policy

Status: **approved for the current milestone**.
Applies to: `GET /events`, `GET /events/{event_id}`, and any future read endpoint over `security_events`.

## Principle

The API exposes the **approved normalized fields only**. It is not a mirror of the
table, and it is not a debug surface. A column being stored does not imply it is
API-facing.

The collector's redaction (`SENSITIVE_KEYS` / `_sanitize()` in
`src/normalization/normalize.py`) is **key-based**. It redacts a value when the
*key* matches. It does not inspect string values. Therefore a secret typed into a
free-text field such as `command` or `message` is stored unredacted, and must not
be exposed on the assumption that "sanitized" means "safe".

## Classification

| Column | Class | Reason |
|---|---|---|
| `event_id` | public | SHA-256 identifier; opaque, needed for lookup |
| `source` | public | constrained to `cowrie` / `juice_shop` |
| `source_event_id` | internal | source-internal identifier; no API value |
| `event_timestamp` | public | primary ordering field |
| `collected_at` | public | ingestion ordering field |
| `event_type` | public | source-defined event type |
| `session_id` | public | opaque; required for correlation |
| `scenario_id` | public | controlled-test metadata |
| `test_run_id` | public | controlled-test metadata |
| `src_ip` | public | primary analytic signal |
| `protocol` | public | `ssh` / `http` |
| `username` | internal | attacker-supplied string; may contain credentials |
| `command` | internal | free text; key-based redaction does not catch inline secrets |
| `http_method` | public | small enum |
| `route` | public | path only — see dependency below |
| `status_code` | public | integer |
| `message` | internal | free text; often embeds the command |
| `metadata` | never | source-specific JSON; key-redaction only |
| `raw_event` | never | source-specific JSON; duplicates every other column |

## API-facing contract

`GET /events` and `GET /events/{event_id}` return exactly these fields:

```
event_id, source, event_timestamp, collected_at, event_type, session_id,
scenario_id, test_run_id, src_ip, protocol, http_method, route, status_code
```

`raw_event`, `metadata`, `command`, `message`, and `username` are **never**
returned. Absent, not null, not truncated.

## Dependencies and conditions

1. **`route` is public only while Nginx logs `$uri`.** `config/nginx/default.conf`
   uses `route: $uri`, which excludes the query string. If the format changes to
   `$request_uri`, `route` must be reclassified as internal in the same change.
2. **No value-level scrubber is assumed.** If one is added later, it is a separate
   reviewed change; this policy is not silently upgraded by it.
3. **No single-event endpoint exists yet.** If one is added, `command`, `message`,
   and `username` still require an explicit, separately approved policy. Truncation
   alone is not accepted as a safety measure.

## Database enforcement

The `honeytrace_api` role receives **column-level** `SELECT` on the public columns
only (see `sql/002_create_api_readonly_role.sql`). The database therefore enforces
this policy independently of the application code: a query that selects
`raw_event` or `metadata` fails rather than leaking.

Never grant table-level `SELECT` to `honeytrace_api` — a table-level grant includes
every column and would silently defeat this policy.

## Changing this policy

Any change to the classification table requires review by the data-pipeline owner
and a matching update to the column grants. Code alone must never widen the
contract.
