#!/bin/sh
# Runs once, on first database initialization only (empty data volume).
# Sets the password for the honeytrace_pipeline role.
#
# Password safety:
#   - The password is written to a temporary file (mode 0600), never to
#     process arguments or the SQL file.
#   - psql reads it via \set with backticks (psql internal variable, not
#     shell expansion). The password flows through stdin, not process args.
#   - :'password' is psql's safe-quoting syntax (prevents SQL injection).
#   - SET log_statement = 'none' prevents the password from appearing in logs.
#   - The temp file is deleted after use.

set -eu

: "${PIPELINE_DATABASE_PASSWORD:?PIPELINE_DATABASE_PASSWORD must be set}"

PWFILE=/tmp/.pw_init_pipeline
printf '%s' "$PIPELINE_DATABASE_PASSWORD" > "$PWFILE"
chmod 600 "$PWFILE"

psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" \
     --dbname "$POSTGRES_DB" <<'SQL'
\set password `cat /tmp/.pw_init_pipeline`
SET log_statement = 'none';
ALTER ROLE honeytrace_pipeline PASSWORD :'password';
SET log_statement = 'ddl';
SQL

rm -f "$PWFILE"
