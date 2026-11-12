# HoneyTrace AI — Detection and Incident Integration Contract

**Status:** Proposal, pending validation by Person 1 and Person 3.
Field names reflect `docs/sample-output.json`, produced by the code on branch `feature/detection-ml`. The code is tested and is the reference.

## 1. Existing event source

The `security_events` table remains the source of truth for collected, normalized events.

The detection engine reads normalized events and never modifies or deletes them. Every detection and incident keeps explicit references to `security_events.event_id` values.

`scenario_id` and `test_run_id` are optional and only set from verified test context. Neither of them, nor an identical IP address, proves that two events are related. The engine never correlates events by IP.

## 2. Detection

A detection is a finding produced by one rule. It is a signal, not a confirmed attack.

| Field | Type | Description |
|---|---|---|
| `detection_id` | string | SHA-256 of `rule_id` and the sorted `source_event_ids`. Deterministic. |
| `rule_id` | string | Identifier of the rule that fired. |
| `description` | string | Fixed text describing the rule. |
| `detector_version` | string | Version of the rule set that produced the finding (for traceability). |
| `severity` | string | `low`, `medium`, `high` or `critical`. |
| `source_event_ids` | list of string | `event_id` values of the supporting events. |
| `evidence` | object | Allowlisted, sanitized fields. Never contains commands, messages or passwords. |
| `created_at` | ISO 8601 UTC | Time the detection was produced by the engine. |

Notes:
- `detector_version` is a separate field. It is NOT part of `detection_id`, so changing a rule does not create duplicate detections.
- Reprocessing the same events yields the same `detection_id`.
- There is no `confidence` field: rules have no computed confidence, so none is invented.
- Detections are inserted with `ON CONFLICT (detection_id) DO NOTHING` and are never deleted.

## 3. Incident

An incident groups the detections of one verified session. Events are linked only through a verified `session_id`, never through an IP address.

| Field | Type | Description |
|---|---|---|
| `incident_id` | string | 64-character SHA-256 of `source` and `session_id`. Stable when evidence is added. The dashboard may display the first 12 characters only. |
| `title` | string | Generic title. Contains no text taken from events. |
| `summary` | string | Number of detections, rule IDs and number of events. |
| `severity` | string | Highest severity among linked detections. |
| `status` | string | `open`, `under_review`, `resolved` or `false_positive`. |
| `created_at`, `updated_at` | ISO 8601 UTC | Creation and last engine update. |
| `source` | string | Event source (for example `cowrie`). |
| `session_id` | string | Verified session identifier. |
| `detection_ids` | list of string | Linked detections. |
| `event_ids` | list of string | Events of the session, in chronological order. |
| `missing_event_ids` | list of string | Events cited by a detection but absent from the analysed batch. This does NOT prove that an event was deleted. |
| `timeline` | list of object | Chronological entries: `timestamp`, `event_id`, `event_type`, `source`, `detection_ids`. |

Notes:
- By default an incident is created only when its severity is `medium` or higher.
- Juice Shop events have no `session_id` (the Nginx log has no session identifier), so they produce detections but no incidents.
- Detections and incidents use different names on purpose: `source_event_ids` for detections, `event_ids` for incidents.

## 4. Status and update policy (proposal)

The engine owns the evidence: detections, events, timeline, severity, summary and `updated_at`. Analysts own `status`.

- A new incident is created with `status = open`.
- A re-run of the engine NEVER modifies `status`.
- Severity is recalculated by the engine as the maximum over linked detections.
- Detections are never deleted.

Decisions needed from the team:
1. Does a `resolved` incident reopen when new evidence arrives? Proposal: no. Expose a boolean `has_new_evidence` instead.
2. What happens to a `false_positive` incident on new evidence? Proposal: keep the status and set the same `has_new_evidence` flag.
3. Should severity be allowed to decrease? Proposal: no, it can only rise.

## 5. Proposed persistence (Person 1 owns the migration, Person 3 reviews)

These are proposals only. Person 1 decides the final schema (link tables, indexes).

### Table `detections`

| Column | Type | Note |
|---|---|---|
| `detection_id` | text PRIMARY KEY | SHA-256 |
| `rule_id` | text NOT NULL | |
| `description` | text NOT NULL | |
| `severity` | text NOT NULL | CHECK in (`low`,`medium`,`high`,`critical`) |
| `source_event_ids` | text[] NOT NULL | references `security_events.event_id` |
| `evidence` | jsonb NOT NULL | allowlisted fields only |
| `detector_version` | text NOT NULL | |
| `created_at` | timestamptz NOT NULL | |

### Table `incidents`

| Column | Type | Note |
|---|---|---|
| `incident_id` | text PRIMARY KEY | SHA-256 |
| `source`, `session_id` | text NOT NULL | UNIQUE together |
| `title`, `summary` | text NOT NULL | |
| `severity` | text NOT NULL | CHECK as above |
| `status` | text NOT NULL DEFAULT `open` | CHECK in (`open`,`under_review`,`resolved`,`false_positive`). Never overwritten by the engine. |
| `detection_ids`, `event_ids`, `missing_event_ids` | text[] | or link tables |
| `timeline` | jsonb | or rebuilt from `security_events` |
| `created_at`, `updated_at` | timestamptz NOT NULL | |

The upsert of an incident updates only engine-owned columns (`severity`, `summary`, `updated_at`, id lists), never `status`.

## 6. Evidence and redaction

- Evidence is built from an allowlist of fields: `event_type`, `session_id`, `src_ip`, `protocol`, `username`, `http_method`, `route`, `status_code`, plus counts and timestamps.
- Command text, `message`, `metadata` and `raw_event` are never copied into detections, incidents, timelines or exports.
- Passwords are already redacted by the normalizer before the engine receives events.
- The API must not expose `raw_event`. The final redaction policy and the API allowlist are decided by the team.

## 7. Known limitations

- Threshold and sequence rules group by `session_id` only, not by `(source, session_id)`. The risk is low (Cowrie session IDs are random, Juice Shop has none) and will be fixed later.
- Juice Shop routes come from `$uri`, so the query string and the body are not visible to the rules.
- Cowrie command rules read `command`, then `metadata["input"]`. The real field name is to be confirmed by Person 1 on an anonymized sample.

## 8. Decisions requiring team confirmation

- Status update policy (section 4).
- Final schema, constraints and migration owner (section 5).
- Redaction policy and API response allowlist.
- Redaction of query strings if `$request_uri` is added to the Nginx log.
- Manifest format for labels: it must contain a label per `session_id`, not only per `test_run_id`.