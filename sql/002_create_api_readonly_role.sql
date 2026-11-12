-- STATUS: APPLIED to the local Docker database; still requires review before merge.
--
-- Creates the read-only role used by the API.
-- The password is set interactively and never stored in this file:
--     psql -U hive -d honeytrace
--     \password honeytrace_api
--
-- Boundary:
--   collector account : INSERT on security_events
--   honeytrace_api    : SELECT on approved columns only
--   API               : no INSERT / UPDATE / DELETE
--   raw_event, metadata, command, message, username : no SELECT for the API role
--
-- Assumes the database is named "honeytrace" (see .env.example).

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'honeytrace_api') THEN
        CREATE ROLE honeytrace_api LOGIN;
    END IF;
END
$$;

GRANT CONNECT ON DATABASE honeytrace TO honeytrace_api;
GRANT USAGE ON SCHEMA public TO honeytrace_api;

-- Column-level SELECT matching docs/api-field-policy.md.
GRANT SELECT (
    event_id,
    source,
    event_timestamp,
    collected_at,
    event_type,
    session_id,
    scenario_id,
    test_run_id,
    src_ip,
    protocol,
    http_method,
    route,
    status_code
) ON security_events TO honeytrace_api;

-- Deliberately NOT granted: raw_event, metadata, command, message, username.
-- Deliberately NOT granted: INSERT, UPDATE, DELETE, TRUNCATE, or any table-level SELECT.
-- A table-level GRANT SELECT ON security_events would include every column and
-- silently defeat the column-level policy above.
