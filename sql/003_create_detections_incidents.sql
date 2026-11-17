-- sql/003_create_detections_incidents.sql
-- Detections and incidents, following docs/integration-contract.md sections 2-5.
-- security_events stays the source of truth and is NOT modified here.
-- Safe to re-run (IF NOT EXISTS / OR REPLACE / DROP TRIGGER IF EXISTS).

CREATE TABLE IF NOT EXISTS detections (
    detection_id      text PRIMARY KEY
                      CHECK (detection_id ~ '^[0-9a-f]{64}$'),
    rule_id           text NOT NULL CHECK (rule_id <> ''),
    description       text NOT NULL,
    detector_version  text NOT NULL,
    severity          text NOT NULL
                      CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    -- event_id values of security_events. Not a foreign key on purpose: the
    -- contract allows citing events absent from the analysed batch, and
    -- security_events.event_id is CHAR(64) while this is text.
    source_event_ids  text[] NOT NULL CHECK (cardinality(source_event_ids) > 0),
    -- Allowlisted projection: the ONLY evidence column the API role may read.
    evidence_public   jsonb NOT NULL DEFAULT '{}'::jsonb
                      CHECK (jsonb_typeof(evidence_public) = 'object'
                             AND NOT (evidence_public ?| ARRAY[
                                 'username', 'password', 'command',
                                 'message', 'metadata', 'raw_event'])),
    -- Full evidence (includes username). Stored for analysts, never served.
    evidence_internal jsonb NOT NULL DEFAULT '{}'::jsonb
                      CHECK (jsonb_typeof(evidence_internal) = 'object'),
    created_at        timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id       text PRIMARY KEY
                      CHECK (incident_id ~ '^[0-9a-f]{64}$'),
    -- '|' is the separator inside the incident_id formula, so it must never
    -- appear in either part (otherwise two sessions could share a hash input).
    source            text NOT NULL
                      CHECK (source <> '' AND position('|' in source) = 0),
    session_id        text NOT NULL
                      CHECK (session_id <> '' AND position('|' in session_id) = 0),
    title             text NOT NULL,
    summary           text NOT NULL,
    severity          text NOT NULL
                      CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status            text NOT NULL DEFAULT 'open'
                      CHECK (status IN ('open', 'under_review', 'resolved', 'false_positive')),
    has_new_evidence  boolean NOT NULL DEFAULT false,
    detection_ids     text[] NOT NULL DEFAULT '{}',
    event_ids         text[] NOT NULL DEFAULT '{}',
    missing_event_ids text[] NOT NULL DEFAULT '{}',
    timeline          jsonb NOT NULL DEFAULT '[]'::jsonb
                      CHECK (jsonb_typeof(timeline) = 'array'),
    created_at        timestamptz NOT NULL,
    updated_at        timestamptz NOT NULL,
    UNIQUE (source, session_id),
    -- Contract section 3: SHA-256 of the UTF-8 string 'incident|<source>|<session_id>',
    -- lowercase hex, no trimming, no case change. The database refuses any other id,
    -- so the engine and the API can never disagree about it.
    CONSTRAINT incident_id_matches_session CHECK (
        incident_id = encode(
            sha256(convert_to('incident|' || source || '|' || session_id, 'UTF8')),
            'hex')
    )
);

CREATE INDEX IF NOT EXISTS idx_detections_source_events
    ON detections USING gin (source_event_ids);
CREATE INDEX IF NOT EXISTS idx_detections_created
    ON detections (created_at DESC, detection_id DESC);
CREATE INDEX IF NOT EXISTS idx_detections_rule
    ON detections (rule_id);

-- The incident API lists incidents ORDER BY updated_at DESC, incident_id DESC
-- (src/api/incidents.py), so the index follows that key.
DROP INDEX IF EXISTS idx_incidents_created;
CREATE INDEX IF NOT EXISTS idx_incidents_updated
    ON incidents (updated_at DESC, incident_id DESC);

-- Detections are append-only (contract section 2): inserted with
-- ON CONFLICT DO NOTHING, never updated, never deleted.
-- (TRUNCATE is not blocked here; do not grant it to application roles.)
CREATE OR REPLACE FUNCTION detections_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'detections are append-only (docs/integration-contract.md section 2)';
END
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS detections_append_only ON detections;
CREATE TRIGGER detections_append_only
    BEFORE UPDATE OR DELETE ON detections
    FOR EACH ROW EXECUTE FUNCTION detections_append_only();

-- Severity is monotonic (contract section 4): it can rise, never fall.
-- A lower value is ignored rather than rejected, so that re-running the engine
-- on a partial batch stays idempotent instead of failing the upsert.
CREATE OR REPLACE FUNCTION incidents_keep_severity() RETURNS trigger AS $$
DECLARE
    old_rank int;
    new_rank int;
BEGIN
    old_rank := CASE OLD.severity WHEN 'low' THEN 1 WHEN 'medium' THEN 2
                                  WHEN 'high' THEN 3 WHEN 'critical' THEN 4 END;
    new_rank := CASE NEW.severity WHEN 'low' THEN 1 WHEN 'medium' THEN 2
                                  WHEN 'high' THEN 3 WHEN 'critical' THEN 4 END;
    IF new_rank < old_rank THEN
        NEW.severity := OLD.severity;
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS incidents_keep_severity ON incidents;
CREATE TRIGGER incidents_keep_severity
    BEFORE UPDATE ON incidents
    FOR EACH ROW EXECUTE FUNCTION incidents_keep_severity();