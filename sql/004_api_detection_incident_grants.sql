-- sql/004_api_detection_incident_grants.sql
-- Column-level grants for the read-only API role on the new tables.
-- No table-level SELECT anywhere: every readable column is listed.
-- Requires sql/002 (creates honeytrace_api) and sql/003 (creates the tables).

REVOKE ALL ON detections, incidents FROM PUBLIC;
REVOKE ALL ON detections, incidents FROM honeytrace_api;

-- evidence_internal is deliberately absent: it holds username.
GRANT SELECT (
    detection_id, rule_id, description, detector_version, severity,
    source_event_ids, evidence_public, created_at
) ON detections TO honeytrace_api;

-- missing_event_ids is deliberately absent: its exposure is still an open
-- team decision (docs/integration-contract.md section 8). Adding it later is a
-- one-line grant: GRANT SELECT (missing_event_ids) ON incidents TO honeytrace_api;
GRANT SELECT (
    incident_id, source, session_id, title, summary, severity, status,
    has_new_evidence, detection_ids, event_ids, timeline, created_at, updated_at
) ON incidents TO honeytrace_api;

-- The API role stays read-only: no INSERT, UPDATE or DELETE.
-- When the API gets an analyst "change status" endpoint, give it its own
-- narrow grant, e.g. GRANT UPDATE (status, has_new_evidence) ON incidents ...
-- The engine's role (to be created) must NOT be allowed to update "status".