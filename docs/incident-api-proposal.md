# HoneyTrace AI — Incident API Proposal

> **PROPOSAL — NOT APPROVED**
>
> This document is a draft for review. Nothing here is implemented, agreed, or
> authorized. It does not create tables, endpoints, permissions, or migrations.
>
> - **Author:** Person 3 (API and dashboard integration)
> - **Date:** 2026-11-09
> - **Reviewers:** Person 2 (detection and incident contract), Person 1
>   (database schema and migrations), team
> - **Repository state at time of writing:** `master` @ `7e90734`, clean

## How to read this document

Every statement is labelled with one of three markers:

| Marker | Meaning |
|---|---|
| **CONFIRMED** | Person 2 has communicated this decision, but it is **not yet in an updated, merged contract**. It is still subject to being written down and ratified. |
| **PROPOSED** | Person 3's design suggestion. It requires approval before implementation. |
| **OPEN** | Undecided. The owner who must decide is named. |

## Evidence base, and why it matters

| Source | State on 2026-11-09 |
|---|---|
| `docs/integration-contract.md` on `origin/feature/detection-ml` | **Stale.** Last changed 2026-10-30. It still says detections use `event_ids`, that `confidence` exists, that `incident_id` is "preferably a UUID", and it has no `missing_event_ids`, `has_new_evidence`, or status-ownership rule. |
| `docs/sample-output.json` on `origin/feature/detection-ml` | Last changed 2026-11-08. Partially matches Person 2's newer decisions. |
| Person 2's latest decisions | Communicated outside the repository; recorded in §1.1. |
| Database column proposal | **Does not exist yet.** |
| `sql/003` or any incident table | **Does not exist.** |

Consequence: this proposal cannot be treated as a contract. It records what is
known, what Person 3 proposes, and what remains blocked. When Person 2's updated
contract and column proposal land, this document must be reconciled against them
line by line before any implementation begins.

---

## 1. Purpose and scope

### 1.1 Decisions communicated by Person 2

These are **CONFIRMED** as communicated, not yet ratified in a merged document.

- Detections reference events with `source_event_ids`.
- Incidents reference events with `event_ids`.
- Both names remain because they describe different relationships.
- `incident_id` is a 64-character SHA-256 hash derived from `(source, session_id)`.
- The incident ID stays stable when evidence is added.
- The dashboard may display the first 12 characters; the API must preserve the
  full 64-character ID.
- `confidence` does not exist and is excluded.
- `detector_version` is a manually bumped constant, incremented when detection
  rules change, and is **not** included in `detection_id`.
- `description` is a static rule description on detections.
- `missing_event_ids` belongs to incidents: event IDs cited but absent from the
  current batch.
- The detection engine owns evidence and evidence relationships.
- Analysts own incident status.
- Re-runs must never overwrite analyst-managed statuses
  (`under_review`, `resolved`, `false_positive`).
- New evidence on a `resolved` or `false_positive` incident sets
  `has_new_evidence = true` instead of changing status.

### 1.2 Scope of this proposal

**In scope:** a read-only HTTP surface over persisted incidents and their
relationships:

- `GET /incidents`
- `GET /incidents/{incident_id}`

**Out of scope and not authorized by this document:**

- the detection engine, correlation logic, and evidence production (Person 2)
- database schema, migrations, and grants (Person 1)
- incident status changes, acknowledgement, and `has_new_evidence` resets
- a `/detections` endpoint
- dashboard incident views
- AI-assisted explanations
- any write operation of any kind

**Principle:** the API is not a mirror of the database and not a debug surface.
A column being stored does not imply it is API-facing. Any field not explicitly
listed in §7 is denied by default.

---

## 2. Proposed API endpoints

**PROPOSED.** Both endpoints are read-only and require no request body.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/incidents` | List incidents, newest first, cursor paginated |
| `GET` | `/incidents/{incident_id}` | One incident, including its timeline |

### 2.1 `GET /incidents`

Returns a page envelope consistent with `GET /events`:

```json
{
  "items": [ { "...": "incident object, see §5" } ],
  "next_cursor": "opaque-or-null"
}
```

### 2.2 `GET /incidents/{incident_id}`

- `incident_id` must be 64 lowercase hexadecimal characters.
- Returns the same object shape as a list item.
- Unknown but well-formed ID → `404`.
- Malformed ID → `422`, without querying the database.

### 2.3 Explicitly not proposed

- `GET /detections` — **OPEN**. Person 2 has not approved a public detections
  surface. Until then, detection data appears only through incident
  relationships and the timeline.
- Any `POST`, `PATCH`, or `DELETE` — the API remains read-only. Analyst actions
  happen outside this service.

---

## 3. Proposed query parameters and filtering

**PROPOSED.** Final parameter set depends on what Person 1 indexes and what
Person 2 considers a valid filter.

| Parameter | Type | Proposed behaviour |
|---|---|---|
| `limit` | integer, 1–200, default 50 | Page size, mirroring `/events` |
| `cursor` | string | Opaque keyset cursor, see §4 |
| `status` | enum | `open`, `under_review`, `resolved`, `false_positive` |
| `severity` | enum | `low`, `medium`, `high`, `critical` |
| `source` | enum | `cowrie`, `juice_shop` |
| `session_id` | string | Exact match, opaque |
| `has_new_evidence` | boolean | Filter incidents needing analyst review |
| `since` | RFC 3339 timestamp | Inclusive lower bound on the chosen time field |
| `until` | RFC 3339 timestamp | Exclusive upper bound on the chosen time field |

Rules carried over from `/events`:

- Timestamps without a timezone → `400 timestamp_must_include_timezone`.
- Unknown enum values → `422` via validation.
- Only non-empty filters are applied.

**OPEN — Person 2 / Person 1:** whether `since`/`until` filter `created_at` or
`updated_at`, and whether `has_new_evidence` is a supported filter in the first
milestone.

---

## 4. Cursor-based pagination

**PROPOSED, not final.** The shape mirrors the existing `/events` cursor: an
opaque base64url string encoding an ordering key and a tiebreaker, never a raw
offset.

Proposed ordering: `(created_at DESC, incident_id DESC)`, so pages are stable
even when several incidents share a timestamp. The next cursor would encode the
last returned row's ordering values.

**OPEN — Person 2 / Person 1:**

1. Is the sort key `created_at` or `updated_at`? `updated_at` changes when
   evidence arrives, which makes a cursor unstable mid-pagination.
2. Should the cursor be bound to the active filter set, so a cursor cannot be
   reused with different filters? `/events` does not do this today.
3. What index supports the chosen ordering? This is Person 1's decision.

No cursor format is fixed by this document. The implementation must not guess
it before the sort key and index are agreed.

---

## 5. Proposed incident response structure

**PROPOSED.** The example below contains only fields this proposal considers
public, and deliberately omits every field listed as OPEN in §7.

```json
{
  "incident_id": "9259e74e52c45c3b04a5e9dbb45057e06427c9daa8430a21aaca74ae5d6de6b6",
  "title": "Suspicious activity in session real-1",
  "summary": "7 detection(s) linked by session over 6 event(s).",
  "severity": "medium",
  "status": "open",
  "source": "cowrie",
  "session_id": "real-1",
  "created_at": "2026-11-08T12:00:00Z",
  "updated_at": "2026-11-08T12:00:00Z",
  "has_new_evidence": false,
  "detection_ids": [
    "4f3ecf55b447f543f85e913fcf8bf9616faff028d14785c52358db45b98096b0"
  ],
  "event_ids": [
    "470b5f71af2285dead38e2a538175d0b99e057b3950ffd2dc18e92230c22a897"
  ],
  "timeline": [
    {
      "event_id": "470b5f71af2285dead38e2a538175d0b99e057b3950ffd2dc18e92230c22a897",
      "event_type": "cowrie.login.failed",
      "source": "cowrie",
      "timestamp": "2026-10-28T10:00:00Z",
      "detection_ids": [
        "4f3ecf55b447f543f85e913fcf8bf9616faff028d14785c52358db45b98096b0"
      ]
    }
  ]
}
```

Notes:

- `has_new_evidence` does **not** appear in the current `sample-output.json`.
  It is **PROPOSED** here because Person 2 described the flag, but its exposure
  and exact type are **OPEN**.
- All IDs are opaque 64-character hashes. The full `incident_id` is preserved;
  truncation to 12 characters is a dashboard concern only.
- `timeline` entries contain only field names already public on events
  (`event_id`, `event_type`, `source`, `timestamp`) plus `detection_ids`.
- `evidence` and `missing_event_ids` are intentionally absent from this example.
  See §7 and §9.

**Fields deliberately absent and why**

| Field | Why absent |
|---|---|
| `evidence` | Contains `username` today; exposure is unapproved (§9) |
| `missing_event_ids` | Classification is OPEN; it reveals referential gaps |
| `description` | Belongs to detections, not incidents; no public detections endpoint approved |
| `detector_version` | Detection-level; exposure is OPEN |
| `raw_event`, `metadata`, `command`, `message`, `username`, `source_event_id` | Never exposed (§8) |

---

## 6. Detection and incident relationship fields

**CONFIRMED semantics**, with one structural OPEN item.

| Field | Belongs to | Meaning |
|---|---|---|
| `source_event_ids` | detection | The events that triggered this detection |
| `event_ids` | incident | The events in the incident's scope |
| `detection_ids` | incident | Detections linked to the incident |
| `missing_event_ids` | incident | IDs cited by detections but absent from the current batch |
| `detection_id` | detection | Stable identity; excludes `detector_version` |
| `detector_version` | detection | Manually bumped constant |
| `description` | detection | Static rule description |
| `confidence` | — | Removed; must not appear |

`source_event_ids` and `event_ids` are not synonyms:

- `source_event_ids` is the **evidence chain** for one detection.
- `event_ids` is the **scope** of the incident, which may include contextual
  events not attached to any single detection.

**OPEN — Person 1 / Person 2:** whether `event_ids` is stored directly on the
incident or derived through detections, and whether a separate
`incident_events` relationship table is needed. The stale contract §4 raises
both possibilities without deciding.

---

## 7. Public-field allowlist

**PROPOSED.** Default deny: anything not listed as public is not returned.

| Field | Proposed class | Note |
|---|---|---|
| `incident_id` | public | 64 lowercase hex, full value |
| `title` | public | Analyst/engine text; no secrets expected, but see note below |
| `summary` | public | Generated from rule IDs and counts |
| `severity` | public | Enum |
| `status` | public | Enum |
| `source` | public | `cowrie` / `juice_shop` |
| `session_id` | public | Already public on events |
| `created_at` | public | UTC |
| `updated_at` | public | UTC |
| `has_new_evidence` | **OPEN** | Person 2 proposed the flag; exposure needs approval |
| `detection_ids` | public | Opaque hashes |
| `event_ids` | public | Opaque hashes |
| `timeline` | public | Only safe fields; see §5 |
| `missing_event_ids` | **OPEN** | Referential-gap information |
| `evidence` | **OPEN** | See §9 |
| `description` | **OPEN** | Detection-level; requires a detections surface |
| `detector_version` | **OPEN** | Detection-level |
| `confidence` | never | Removed by Person 2 |
| `raw_event`, `metadata`, `command`, `message`, `username`, `source_event_id` | never | §8 |

Note on `title` and `summary`: these are generated text, not raw event fields.
They must still be checked for embedded secrets before exposure, because a rule
could interpolate a command or username into them. This is a **PROPOSED**
validation requirement, not an existing guarantee.

The 13 approved event fields remain exactly as they are today. This proposal
does not widen the event contract.

---

## 8. Restricted-field policy

**CONFIRMED policy.** The following are never exposed through the API, the
dashboard, AI prompts, or logs:

```
raw_event, metadata, command, message, username, source_event_id
```

Additional rules:

1. **Nesting does not sanitise.** A forbidden field inside `evidence`, inside a
   timeline entry, or inside any nested JSON object is still forbidden.
2. **"Sanitized" is not assumed.** The collector's redaction is key-based; a
   secret typed into a free-text value is not removed by it.
3. **No truncation as a safety measure.** Truncating `command` still exposes
   `command`.
4. **Enforcement is layered:**
   - PostgreSQL column-level `SELECT` grants for `honeytrace_api`
   - Pydantic response models with `extra="forbid"`
   - an explicit allowlist in the API layer
   - contract tests that scan the generated OpenAPI document for forbidden names
5. **Changing this list** requires review by the data-pipeline owner and a
   matching change to the database grants. Code alone must never widen it.

The current `sample-output.json` detection evidence contains a `username` key
(value deliberately not reproduced here). That field is forbidden. See §9.

---

## 9. Evidence exposure options requiring team approval

**OPEN — Person 2 and Person 1 must decide.** This is the single largest
unresolved security question in the incident design.

### Option A — Never expose evidence (recommended for the first milestone)

The API returns incident-level fields and the timeline only. Evidence stays
inside the detection engine and the database.

- **Pros:** smallest attack surface; no new redaction policy; consistent with
  the current event API, which exposes no evidence.
- **Cons:** analysts cannot see rule reasoning through the API.
- **Approval:** Person 2 (evidence semantics), Person 1 (field policy).

### Option B — Expose a fixed, per-rule allowlist of evidence keys

Only named keys are returned, for example `event_type`, `session_id`, `src_ip`,
`count`, `first_event_at`, `last_event_at`, `window_seconds`. Any key not on the
list is dropped, at every nesting depth.

- **Pros:** useful reasoning without exposing free text.
- **Cons:** requires a per-rule schema and tests; rules evolve, so the allowlist
  must be reviewed whenever a rule changes.
- **Approval:** Person 2 for the key list, Person 1 for the policy, team for the
  change control.

### Option C — Expose evidence as redacted free-form JSON

Not recommended.

- **Why not:** key-based redaction does not inspect values; secrets embedded in
  strings survive. It would also make the response shape unstable per rule.
- **Approval:** would require a value-level scrubber, which does not exist and
  is explicitly out of scope in `docs/api-field-policy.md`.

**Until one option is approved, implementation must assume Option A.**

---

## 10. Incident status and `has_new_evidence`

**CONFIRMED ownership model:**

- The detection engine owns evidence and evidence relationships.
- Analysts own incident status.
- Re-runs must not overwrite `under_review`, `resolved`, or `false_positive`.
- New evidence on a `resolved` or `false_positive` incident sets
  `has_new_evidence = true` rather than changing status.
- The engine currently emits `status = open` when creating an incident.

**OPEN — Person 2 and team:**

1. **Reset mechanism.** Who clears `has_new_evidence`, at what point, and
   through what interface? The API is read-only, so acknowledgement cannot
   happen here.
2. **Scope of the flag.** Does it apply only to `resolved` / `false_positive`,
   or also to `open` / `under_review`?
3. **Representation.** Boolean, or a timestamp such as
   `has_new_evidence_since`? A timestamp carries more information but is a
   different contract.
4. **API exposure.** Should the flag be returned by `/incidents`? It is
   **PROPOSED** in §5 but not approved.
5. **Status transitions.** Are `resolved → under_review` and
   `false_positive → under_review` allowed, and by whom? The stale contract
   lists statuses but defines no transition table.

Because this API is read-only, none of these decisions are implementable as
write endpoints here. They affect what the API **reads and returns**, not what
it changes.

---

## 11. Required database tables and read-only permissions

**This section is a dependency description, not a DDL proposal.** Column types,
constraints, and final table shapes are Person 1's and Person 2's to define.

### 11.1 Logical data the API would need to read

| Data | Source |
|---|---|
| Incident identity and metadata | `incidents` |
| `detection_ids` per incident | `incident_detections` (or equivalent) |
| `event_ids` per incident | stored on the incident, or derived through detections, or `incident_events` (**OPEN**) |
| Timeline rows | incident event IDs joined to `security_events` |
| `has_new_evidence` | `incidents` (**OPEN** representation) |

Timeline reads only `security_events.event_id`, `event_type`, `source`, and
`event_timestamp` — all already granted to `honeytrace_api` by `sql/002`. No new
event-column grant is required for the timeline as proposed.

### 11.2 Candidate tables

Candidate names only, taken from the stale contract §4 and not approved:

- `detections`
- `detection_events`
- `incidents`
- `incident_detections`
- possibly `incident_events`

### 11.3 Read-only permission requirements

- **Column-level** `GRANT SELECT` for `honeytrace_api` on the public columns of
  the incident and relationship tables.
- **No table-level `SELECT`** on any table. A table-level grant includes every
  column and silently defeats the allowlist.
- **No** `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`, or ownership rights.
- The existing `honeytrace_api` role should be extended, not replaced.
- Grants must be written and reviewed by Person 1, with the same review standard
  applied to `sql/002`.
- A regression test equivalent to `tests/test_api_db_permissions.py` should be
  extended to the new tables once they exist.

### 11.4 Indexes

Pagination requires an index matching the approved sort key. Index design is
**OPEN** and belongs to Person 1.

---

## 12. Expected HTTP errors

**PROPOSED**, mirroring `/events` exactly so the dashboard and clients behave
consistently.

| Status | `detail` | Cause |
|---|---|---|
| `200` | — | success |
| `400` | `invalid_cursor` | cursor is malformed or unparseable |
| `400` | `timestamp_must_include_timezone` | `since`/`until` without a timezone |
| `404` | `incident_not_found` | well-formed ID, no such incident |
| `422` | validation body | malformed `incident_id`, bad enum, `limit` outside 1–200 |
| `503` | `database_not_configured` | `API_DATABASE_URL` absent |
| `503` | `database_unavailable` | database unreachable or query failed |

Rules:

- No database error text, DSN, or credential may appear in any response.
- A malformed `incident_id` must be rejected before any query runs.
- The API never returns `500` for a client input error.

---

## 13. Dependencies on Person 1 and Person 2

Status as of 2026-11-09.

| # | Dependency | Owner | Status | Blocks |
|---|---|---|---|---|
| 1 | Updated `docs/integration-contract.md` | Person 2 | **Not available** (file is from 2026-10-30) | everything |
| 2 | Updated `docs/sample-output.json` | Person 2 | Partially matches | response shape |
| 3 | Database column proposal | Person 2 | **Absent** | migration, response model |
| 4 | Exact `incident_id` canonicalisation for `(source, session_id)` | Person 2 | **Absent** | ID validation, reproducibility |
| 5 | Evidence exposure decision (§9) | Person 2 + Person 1 | **Open** | whether evidence can ever be returned |
| 6 | `has_new_evidence` representation and reset | Person 2 + team | **Open** | response field |
| 7 | `missing_event_ids` classification | Person 2 | **Open** | response field |
| 8 | `sql/003` tables, constraints, indexes | Person 1 | **Not started** | all queries |
| 9 | Column-level grants on new tables | Person 1 | **Not started** | API access |
| 10 | Pagination sort key and index | Person 1 | **Open** | list endpoint |
| 11 | Manifest `session_id` per label (Dorsaf) | Person 1 / Dorsaf | **Open** | test-run context |
| 12 | Cowrie command source field documentation | Person 1 | **Not documented** | internal detection only |

### Note on dependency 12

Dorsaf asked for the real Cowrie field containing the command. Current state:

- `docs/event-schema.md:24` says only `command | string/null | Command, when available`.
- `src/normalization/normalize.py:137` reads `raw_event["command"]`.
- Cowrie's actual field is `input` on `cowrie.command.input` events, and `input`
  is not in `KNOWN_COLUMNS`; the string `"input"` does not appear anywhere in
  `src/`.

So today a real Cowrie command would likely land in `metadata.input`, leaving
`command` NULL. This is Person 1's component. Whatever the mapping becomes,
`command` and `input` remain internal and never reach the API, dashboard, or AI
prompts.

---

## 14. Open questions and approval checklist

### 14.1 Questions requiring an answer before implementation

| # | Question | Owner |
|---|---|---|
| Q1 | When will the updated contract, sample output, and column proposal be pushed? | Person 2 |
| Q2 | What exact byte string is hashed to produce `incident_id`? (delimiter, case, encoding) | Person 2 |
| Q3 | Is `event_ids` stored directly, derived through detections, or via `incident_events`? | Person 2 + Person 1 |
| Q4 | Which evidence option in §9 is approved? | Person 2 + Person 1 |
| Q5 | Is `missing_event_ids` public or internal? | Person 2 |
| Q6 | Is `has_new_evidence` public, and is it a boolean or a timestamp? | Person 2 |
| Q7 | Who resets `has_new_evidence`, and through what mechanism? | Person 2 + team |
| Q8 | Is `/detections` ever public, and in which milestone? | Person 2 |
| Q9 | Is the sort key `created_at` or `updated_at`? | Person 2 + Person 1 |
| Q10 | Which filters are supported in the first milestone? | Person 2 |
| Q11 | Which indexes will support pagination? | Person 1 |
| Q12 | When will `sql/003` and the matching column-level grants land? | Person 1 |
| Q13 | Are `title` and `summary` guaranteed free of embedded secrets? | Person 2 |
| Q14 | Should the incident API be added to the existing `honeytrace_api` role or a new role? | Person 1 |

### 14.2 Approval checklist

- [ ] Person 2 confirms the field semantics in §6 and the classifications in §7.
- [ ] Person 2 confirms `incident_id` canonicalisation.
- [ ] Person 2 and Person 1 approve an evidence option (§9).
- [ ] Person 2 and the team approve the `has_new_evidence` contract (§10).
- [ ] Person 1 approves the required reads and index design (§11).
- [ ] Person 1 confirms column-level grants with no table-level `SELECT`.
- [ ] Team approves the endpoint list in §2.
- [ ] Team approves the error contract in §12.

### 14.3 What happens after approval

Only then would Person 3:

1. reconcile this document with the updated contract and column proposal;
2. add Pydantic response models and the two read-only routes;
3. extend the field-contract tests to the incident allowlist;
4. extend the database permission tests to the new tables;
5. update the dashboard to consume the API.

No step above is authorized by this document.
