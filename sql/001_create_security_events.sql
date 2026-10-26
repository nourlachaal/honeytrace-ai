
CREATE TABLE IF NOT EXISTS security_events (
    event_id        CHAR(64) PRIMARY KEY,
    source          TEXT NOT NULL
                    CHECK (source IN ('cowrie', 'juice_shop')),
    source_event_id TEXT,
    event_timestamp TIMESTAMPTZ NOT NULL,
    collected_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type      TEXT NOT NULL,
    session_id      TEXT,
    scenario_id     TEXT,
    test_run_id     TEXT,
    src_ip          TEXT,
    protocol        TEXT,
    username        TEXT,
    command         TEXT,
    http_method     TEXT,
    route           TEXT,
    status_code     INTEGER,
    message         TEXT,
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    raw_event       JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp
    ON security_events (event_timestamp);

CREATE INDEX IF NOT EXISTS idx_events_source
    ON security_events (source);

CREATE INDEX IF NOT EXISTS idx_events_session
    ON security_events (session_id);

CREATE INDEX IF NOT EXISTS idx_events_test_run
    ON security_events (test_run_id);
