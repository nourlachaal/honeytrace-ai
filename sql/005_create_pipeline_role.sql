-- sql/005_create_pipeline_role.sql
-- Dedicated role for the scheduled pipeline (CronJob).
-- Least privilege: read events, write detections/incidents, nothing else.
-- Requires sql/001..004 applied first.
-- Password set interactively (never stored in this file):
--     \password honeytrace_pipeline

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'honeytrace_pipeline') THEN
        CREATE ROLE honeytrace_pipeline LOGIN;
    END IF;
END
$$;

GRANT CONNECT ON DATABASE honeytrace TO honeytrace_pipeline;
GRANT USAGE ON SCHEMA public TO honeytrace_pipeline;

-- SELECT: the 13 columns the pipeline reads (EVENT_COLUMNS in src/pipeline.py:33-36).
GRANT SELECT (
    event_id, source, event_type, session_id, event_timestamp,
    src_ip, protocol, username, command, http_method, route, status_code, metadata
) ON security_events TO honeytrace_pipeline;

-- INSERT only on detections (append-only, ON CONFLICT DO NOTHING).
GRANT INSERT (
    detection_id, rule_id, description, detector_version, severity,
    source_event_ids, evidence_public, evidence_internal, created_at
) ON detections TO honeytrace_pipeline;

-- SELECT + INSERT + UPDATE on incidents (UPSERT requires SELECT for conflict check).
GRANT SELECT (
    incident_id, source, session_id, title, summary, severity, status,
    has_new_evidence, detection_ids, event_ids, missing_event_ids, timeline,
    created_at, updated_at
) ON incidents TO honeytrace_pipeline;

GRANT INSERT (
    incident_id, source, session_id, title, summary, severity,
    detection_ids, event_ids, missing_event_ids, timeline,
    created_at, updated_at
) ON incidents TO honeytrace_pipeline;

GRANT UPDATE (
    title, summary, severity, detection_ids, event_ids, missing_event_ids,
    timeline, has_new_evidence, updated_at
) ON incidents TO honeytrace_pipeline;

-- No table-level SELECT, INSERT, UPDATE, DELETE, TRUNCATE anywhere.
-- No access to security_events columns beyond the 13 listed.
-- No access to detections.evidence_internal beyond INSERT (pipeline writes it, never reads it).
