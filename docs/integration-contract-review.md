# Review: Detection and Incident Integration Contract

**Reviewer:** Person 3
**Reviewed revision:** `1100264` (2026-11-12), re-reviewed at `da024a6` (2026-11-16)
**Status:** Complete — B1–B4 closed. The contract is accepted and `sql/003` /
`sql/004` can be written against it.

## 1. Verdict

The contract is implementable. The four blockers raised in the first review are
now resolved in Person 2's code and documentation, not in prose: each one below
records the decision and the test that keeps it true.

This document is the record of those decisions. Where it conflicts with an
earlier chat message, this document wins.

This review approves the data contract. `GET /incidents` is implemented in
PR #6 and answers `503` with a distinct reason until the migrations exist.

## 2. Approved without change

| Item | Note |
|---|---|
| `incident_id` = SHA-256 of `source` + `session_id`, 64 hex | Matches `UNIQUE (source, session_id)`, so identity and uniqueness agree. |
| `detector_version` excluded from `detection_id` | Changing a rule must not create duplicate detections. |
| `ON CONFLICT (detection_id) DO NOTHING`, never deleted | Deterministic reprocessing. |
| No `confidence` field | Rules compute no confidence, so none is invented. |
| Engine owns evidence, analyst owns `status` | The right split, and it matches a read-only API. |
| `missing_event_ids` wording | "Does not prove an event was deleted" prevents a wrong inference in the UI. |
| Juice Shop produces detections but no incidents | Follows from having no `session_id`. Documented, not fixed. |
| §7 confirms `command` falls back to `metadata["input"]` | Superseded: see §6.5. |

## 3. Blockers — all closed

### B1 — `username` must not be served by the API — CLOSED

Resolved by splitting evidence into two columns:

| Column | Granted to `honeytrace_api` | Contents |
|---|---|---|
| `evidence_public` | yes | Projection of `PUBLIC_EVIDENCE_FIELDS` only |
| `evidence_internal` | no | Full evidence, including `username` |

`username` is stored for analysts and never served. The API's SELECT list, its
response models and its OpenAPI document contain no such name, and
`tests/test_incident_field_contract.py` fails if `username`,
`evidence_internal`, `command`, `message`, `raw_event` or `metadata` appears
anywhere in the OpenAPI document.

### B2 — `evidence` and `timeline` as `jsonb` — CLOSED

- **`timeline` is served.** Its keys were verified in
  `src/correlation/timeline.py`: `timestamp`, `event_id`, `event_type`,
  `source`, `detection_ids`. All are already public. The API models it as a
  typed entry with `extra="forbid"`, so a future key fails the request instead
  of being served.
- **`evidence` is not served by v1 of `/incidents`.** `evidence_public` is the
  only evidence column granted, and the endpoint exposes the id lists, the
  timeline and the counts instead. If evidence is ever served, it must be
  re-filtered against the allowlist at the API boundary rather than trusted as
  an upstream projection.

### B3 — `incident_id` byte string — CLOSED

Accepted exactly as implemented:

```python
raw = f"incident|{source}|{session_id}"
incident_id = hashlib.sha256(raw.encode("utf-8")).hexdigest()  # 64 lowercase hex
```

No trimming, no case folding, `|` (0x7C) as separator, no trailing newline.
Test vector: `incident|cowrie|abc123` gives
`000571d6fdf2b9c66be600d604af552ff77b20fa8dac1df75959a1cf11840969`.

Person 3's proposal to hash `lower(trim(source)) + "|" + lower(session_id)` is
**withdrawn**: it produces `38a835c4a76c2a27374c1aa6e1c90f547489aeb7054c8bc6f46d055789b2efb9`
for the same inputs and would fail the golden-vector test. The engine computes
the id; the API reads it and never recomputes it.

### B4 — Grouping key — CLOSED

Threshold and sequence rules now group by `(source, session_id)` in both
`src/detection/engine.py` and `src/correlation/correlator.py`, with tests in
`tests/test_detection_grouping.py`. This matters once several honeypots run at
once, because a Cowrie `session_id` is only unique per instance.

## 4. Answers to the open decisions

### 4.1 — Does a `resolved` incident reopen when new evidence arrives? No

`status` is an analyst judgement and the engine must never reverse it.
`has_new_evidence: boolean` carries the new information instead, and is present
in §3 and §5.

Ownership rule, so that it cannot get stuck and needs no trigger:

- the **writer** only ever sets `has_new_evidence = true`, when new detections
  arrive on a `resolved` or `false_positive` incident;
- the **analyst's** `UPDATE` is the only thing that sets it `false`, and it does
  so together with the status change. Acknowledgement is `status = 'under_review'`.

### 4.2 — What happens to a `false_positive` incident on new evidence? No change

Keep the status, set `has_new_evidence`. If the analyst was wrong, they change
the status themselves.

### 4.3 — Should severity be allowed to decrease? No

Severity is monotonic and becomes a high-water mark. No information is lost
because `status` carries "resolved" and `has_new_evidence` carries "something
changed".

## 5. Requests to Person 2 — status

| # | Request | Status |
|---|---|---|
| 1 | Remove `username` from the §6 allowlist, or state it is stored and never served | Done |
| 2 | Specify the exact `incident_id` byte string | Done |
| 3 | Group rules by `(source, session_id)` | Done, with tests |
| 4 | Add `has_new_evidence` to §3 and §5 | Done |
| 5 | Confirm the `detector_version` format | Done |
| 6 | Open a pull request | Done — PR #5 |
| 7 | Persistence writer: upsert of detections and incidents, engine columns only, `has_new_evidence` computed at write time | Due Wed 18 — gate G3 |
| 8 | A documented batch entry point (read events, run rules, correlate, write) | Missing |
| 9 | Split `numpy` and `scikit-learn` into `requirements-ml.txt` | Requested |

## 6. Requests to Person 1

1. `sql/003` creates **both** `detections` and `incidents`. The API reads these
   incident columns, in this order: `incident_id`, `source`, `session_id`,
   `title`, `summary`, `severity`, `status`, `has_new_evidence`,
   `detection_ids`, `event_ids`, `missing_event_ids`, `timeline`, `created_at`,
   `updated_at`. It reads these detection columns: `detection_id`, `rule_id`,
   `description`, `severity`, `source_event_ids`, `evidence_public`,
   `detector_version`, `created_at`.
2. `sql/004` **extends** `sql/002`: column-level `GRANT SELECT` only, never
   `evidence_internal`, never table-level `SELECT`.
3. `UNIQUE (source, session_id)` on `incidents`; `status` CHECK
   `('open','under_review','resolved','false_positive')`, default `'open'`;
   `severity` CHECK `('low','medium','high','critical')`.
4. `timeline jsonb NOT NULL` and `detection_ids`, `event_ids`,
   `missing_event_ids` `text[] NOT NULL`. A NULL makes the API return 500
   instead of an empty list.
5. The `command` field question is **closed**: `sql/001` already has a
   top-level `command TEXT` column and `src/normalization/normalize.py` emits
   `"command"`. The `metadata["input"]` fallback is dead code and does not need
   confirming on a real sample.

## 7. What this unblocks

`GET /incidents` and `GET /incidents/{incident_id}` are implemented in PR #6
against the 14 columns above, with 26 contract tests. They answer `503` with
`incidents_table_missing`, `incidents_not_granted`, `incidents_unavailable` or
`incidents_not_configured` until the migrations exist, so the endpoint becomes
live the moment `sql/003` and `sql/004` are applied.

Remaining gates:

| Gate | Owner | Due |
|---|---|---|
| `sql/003` + `sql/004` | Person 1 | Mon 16 / Tue 17 |
| Persistence writer | Person 2 | Wed 18 (G3) |
| Batch entry point | Person 2 | Wed 18 |
| Real Cowrie + nginx samples, end to end | Person 1 | Thu 19 |
