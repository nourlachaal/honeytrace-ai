# Review: Detection and Incident Integration Contract

**Reviewer:** Person 3
**Reviewed revision:** `1100264` (2026-11-12)
**Status:** Review complete — 4 items require a decision before `sql/003`

## 1. Verdict

The contract is implementable. Fields, types and the engine/analyst split are
sound, and `incident_id` derived from `source` and `session_id` answers the
question we raised.

Four things must be settled before Person 1 writes `sql/003`: the `username`
allowlist entry (B1), the exposure of `evidence` and `timeline` as `jsonb` (B2),
the exact `incident_id` byte string (B3), and the grouping key used by the rules
versus the key used by incidents (B4).

This review approves the data contract only. It does not approve implementing
`GET /incidents`; that still needs the persistence layer and the evidence
decision below.

## 2. Approved without change

| Item | Note |
|---|---|
| `incident_id` = SHA-256 of `source` + `session_id`, 64 hex | Matches `UNIQUE (source, session_id)` in §5, so identity and uniqueness agree. |
| `detector_version` excluded from `detection_id` | Correct: changing a rule must not create duplicate detections. |
| `ON CONFLICT (detection_id) DO NOTHING`, never deleted | Deterministic reprocessing. |
| No `confidence` field | Rules compute no confidence, so none is invented. |
| Engine owns evidence, analyst owns `status` | The right split, and it matches a read-only API. |
| `missing_event_ids` wording | "Does not prove an event was deleted" prevents a wrong inference in the UI. |
| Juice Shop produces detections but no incidents | Follows from having no `session_id`. |
| §7 confirms `command` falls back to `metadata["input"]` | Matches what the normalizer does today. |

## 3. Blockers

### B1 — `username` must not be served by the API (blocking)

§6 lists `username` in the evidence allowlist, and `docs/sample-output.json`
contains `"username": "root"` in five detections. `docs/api-field-policy.md`
forbids `username` at any nesting depth, and
`tests/test_api_field_contract.py` fails if that name appears anywhere in the
OpenAPI document.

Proposal: keep `username` in `detections.evidence` in the database, but never
serve it. This is what column-level grants are for — the row may hold it, the
API's SELECT list excludes it. The rules do not need it: they group by
`session_id` and count failures.

If the team decides analysts must see `username`, that is a change to
`docs/api-field-policy.md` and needs its own decision. It must not arrive
silently inside an evidence blob.

### B2 — `evidence` and `timeline` as `jsonb` vs the 13-column API contract (blocking)

The API contract is enforced by column-level grants: `honeytrace_api` may
SELECT 13 named columns and nothing else. A `jsonb` column defeats that,
because the grant is on the column, not on its keys. Any key a future rule adds
to `evidence` becomes visible the moment the column is readable.

Proposal:

- **`timeline`** may be served. Its keys are `timestamp`, `event_id`,
  `event_type`, `source` and `detection_ids` — all already public.
- **`evidence`** must not be served as a raw blob. The API selects named keys
  only (`event_type`, `session_id`, `src_ip`, `protocol`, counts, timestamps)
  and never `SELECT evidence` wholesale.
- The field-contract test must be extended to walk **nested** keys. The current
  test scans top-level OpenAPI field names and would not catch `username`
  inside an `evidence` object.

### B3 — `incident_id` canonicalisation is under-specified (blocking)

"SHA-256 of `source` and `session_id`" does not define the byte string.
`cowrie` + `real-1` could be `cowriereal-1`, `cowrie|real-1` or
`cowrie:real-1` — three different hashes for the same session.

Requested: one explicit line, for example

```python
sha256(f"{source}|{session_id}".encode("utf-8")).hexdigest()
```

and a statement of whether `session_id` is trimmed or case-folded before
hashing. If the engine and the API ever compute this independently, a
difference produces duplicate incidents.

### B4 — Rules group by `session_id`, incidents by `(source, session_id)` (blocking)

§7 says threshold and sequence rules group by `session_id` only. §3 says an
incident is identified by `source` + `session_id`. If one session ID ever
appears under two sources, a single detection would span both and could not be
assigned to exactly one incident.

The risk is low today (Cowrie session IDs are random, Juice Shop has none), but
the grouping key should be changed to `(source, session_id)` before detections
are persisted, not after.

## 4. Answers to the open decisions

### 4.1 — Does a `resolved` incident reopen when new evidence arrives? No

`status` is an analyst judgement and the engine must never reverse it: a re-run
is automatic, so it would silently undo a human decision.

Expose `has_new_evidence: boolean` instead. It carries the new information
without overwriting the decision.

Required change: this field does not exist in §3 or §5 today. If we agree to
it, it must be added to both, otherwise it cannot be implemented.

### 4.2 — What happens to a `false_positive` incident on new evidence? No change

Same reasoning: keep the status, set `has_new_evidence`. If the analyst was
wrong, they change the status themselves.

### 4.3 — Should severity be allowed to decrease? No

Severity is monotonic and becomes a high-water mark. This is acceptable because
`status` carries "resolved" and `has_new_evidence` carries "something changed",
so no information is lost.

### 8.1 — Schema owner and grants

Person 1 owns the migration. Requested split:

- `sql/003` creates `detections` and `incidents` per §5, plus `has_new_evidence`.
- `sql/004` adds column-level `GRANT SELECT` for `honeytrace_api`.

The grant must not be "someone will add it later". That is how the 13-column
boundary erodes.

### 8.2 — `timeline` storage

Rebuild it from `security_events` when serving, rather than storing a duplicate
copy. Storing it means two sources of truth for the same facts, and they will
drift.

### 8.3 — `text[]` vs link tables

Acceptable either way. Link tables give indexes and referential integrity;
arrays are simpler and faster to write. Person 1 decides, but the choice should
be recorded in §5.

### 8.4 — Query-string redaction

Defer. The Nginx `route` is `$uri`, which contains no query string, so nothing
changes today. Revisit only if `$request_uri` is ever added.

### 8.5 — Label manifest format

One label per `session_id`, not only per `test_run_id`. Agreed.

## 5. Requests to Person 2

1. Remove `username` from the §6 allowlist, or state explicitly that it is
   stored but never served.
2. Specify the exact `incident_id` byte string and case normalisation (B3).
3. Change the rule grouping key to `(source, session_id)` (B4).
4. Add `has_new_evidence` to §3 and §5 if 4.1 is accepted.
5. Confirm the `detector_version` format and that it is a plain string.

## 6. Requests to Person 1

1. Write `sql/003` from §5, including `has_new_evidence`.
2. Write `sql/004` with column-level grants only. No table-level `SELECT`.
3. Keep `UNIQUE (source, session_id)` on `incidents`.
4. Confirm the `severity` CHECK values match §2.
5. Confirm the real Cowrie field name for command input (`command` vs
   `metadata["input"]`).

## 7. What this unblocks

Once B1–B4 are answered, `sql/003` and `sql/004` can be written, and the
`GET /incidents` response model can be defined against a known shape. Until
then the API will not expose incident data.
