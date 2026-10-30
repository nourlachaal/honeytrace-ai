# HoneyTrace AI — Detection and Incident Integration Contract

**Status:** Draft for team review  
**Scope:** Person 2's detection engine and incident correlation, integrated with the existing event schema and the future FastAPI service.

## 1. Existing event source

The `security_events` table remains the source of truth for collected, normalized events.

The detection engine reads normalized events and does not modify or delete them. Every detection or incident must retain explicit references to the relevant `security_events.event_id` values.

`scenario_id` and `test_run_id` are optional. They may be populated only from verified test-run context. Neither identifier, nor an IP address match alone, proves that two events are causally related.

## 2. Detection model

A detection represents a finding produced by a rule or analytical detector.

Proposed fields:

- `detection_id`: stable identifier.
- `rule_id`: identifier of the rule or detector.
- `detector_version`: version used to produce the finding.
- `severity`: `low`, `medium`, `high`, or `critical`.
- `confidence`: optional numeric score between 0 and 1, when meaningful.
- `event_ids`: references to supporting normalized events.
- `evidence`: sanitized, structured observations explaining the finding.
- `created_at`: UTC timestamp of initial creation.
- `updated_at`: UTC timestamp of the most recent update, if mutable detections are supported.
- `scenario_id`, `test_run_id`: optional verified test context.

### Detection identity and updates

The proposed deterministic identity uses the detector/rule identity and version together with a canonical representation of the event IDs or analysis subject.

Canonical event ID collections must be sorted and deduplicated before hashing.

Repeated processing of the same input with the same detector version must be idempotent.

**Proposed update policy:** if a finding belongs to the same rule, detector version, and analysis subject, retain its `detection_id` when new supporting evidence arrives. Update the evidence and `updated_at`. Preserve prior evidence in an audit history if required by the team.

If a new input represents a distinct analysis subject, create a separate detection. The precise definition of an analysis subject must be agreed for each detector.

## 3. Incident model

An incident represents a case that groups related detections and their supporting events. A detection is not automatically a confirmed incident.

Proposed fields:

- `incident_id`: persistent identifier, preferably a UUID.
- `title`: concise incident title.
- `summary`: evidence-based explanation.
- `severity`: `low`, `medium`, `high`, or `critical`.
- `status`: `open`, `under_review`, `resolved`, or `false_positive`.
- `created_at`: UTC timestamp of creation.
- `updated_at`: UTC timestamp of the most recent change.

### Incident lifecycle

- New incidents begin with status `open`.
- Analysts or approved workflow logic can move an incident to `under_review`.
- An authorized workflow can mark an incident `resolved` or `false_positive`.
- New evidence can update an existing incident without changing its `incident_id`.
- Repeated correlation must not create duplicate incidents for the same case.
- A resolved incident must not be reopened automatically without an explicit, agreed policy.

Incident severity should reflect the available evidence and agreed severity rules. The highest severity among linked detections is a possible starting policy, subject to team approval.

## 4. Relationships and persistence

The existing `security_events` table remains unchanged until persistence changes are approved.

Candidate tables:

- `detections`: one record per detection.
- `detection_events`: links detections to supporting events.
- `incidents`: one record per incident.
- `incident_detections`: links incidents to detections.

Candidate integrity rules:

- Foreign keys from `detection_events.event_id` to `security_events.event_id`.
- Foreign keys from `incident_detections.detection_id` to `detections.detection_id`.
- Unique constraints on `(detection_id, event_id)` and `(incident_id, detection_id)`.
- Transactional updates to prevent partially persisted relationships.
- Explicit handling of missing event references; do not silently create invalid links.

Whether to maintain a separate `incident_events` relationship table should be decided during schema review. Incident event IDs could alternatively be derived through linked detections, but a direct relationship can be useful when an incident includes contextual events not attached to an individual detection.

Database tables and constraints are proposals only; no persistence schema is approved by this document alone.

## 5. Evidence and redaction

Evidence must be structured, sanitized, and traceable to supporting event IDs.

The API must not expose unsanitized `raw_event`. JSON storage alone does not make a payload safe.

The authoritative redaction policy must cover:

- Sensitive key-name variants and nested values.
- Secrets embedded in `command`, `message`, and other free-text fields.
- Authentication credentials, tokens, private keys, and similar sensitive material.
- Safe diagnostic messages that do not reproduce secret-bearing input.

Only approved, sanitized fields may be returned through the API. The redaction policy must be finalized before evidence is exposed.

## 6. API boundary

The detection engine remains independent of collectors and the FastAPI application.

Person 3 may implement the FastAPI skeleton, configuration, and health endpoints before event and incident endpoints are approved.

Event, detection, and incident API response models must wait until the team approves the relevant fields, redaction policy, database permissions, and persistence relationships.

The API should use a separate read-only database role where appropriate. Collector write access must remain separate from API read access.

## 7. Initial tests

Before persistence implementation, tests should cover:

1. Deterministic detection IDs for equivalent inputs.
2. Different IDs for distinct rules, detector versions, or analysis subjects where required.
3. Idempotent reprocessing of the same input.
4. Defined behavior when additional evidence arrives for an existing detection.
5. Valid event references and handling of missing event IDs.
6. Duplicate relationship prevention.
7. Correlation across events only when sufficient evidence exists.
8. No causal correlation based solely on source IP, scenario ID, or test run ID.
9. Incident identity stability when new detections or events are linked.
10. Valid severity and status transitions.
11. Sanitization of evidence before exposure.
12. Preservation of existing `security_events` records.

## 8. Decisions requiring team confirmation

- Exact detection identity and analysis-subject definition.
- Detection evidence update and audit-history policy.
- Incident severity aggregation and status-transition rules.
- Whether resolved incidents can be reopened and under which conditions.
- Whether an `incident_events` table is necessary.
- Final foreign keys, uniqueness constraints, and transaction behavior.
- Final redaction policy and API response allowlist.

Implementation of persistence and event/incident API endpoints begins only after these decisions are reviewed and approved.