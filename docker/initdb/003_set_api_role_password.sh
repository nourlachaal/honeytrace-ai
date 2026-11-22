#!/bin/sh
# Runs once, on first database initialization only (empty data volume).
# SQL init scripts cannot read environment variables, so the read-only role's
# password is set here instead.
#
# Password safety:
#   - The password is written to a temporary file (mode 0600), never to
#     process arguments or the SQL file.
#   - psql reads it via \set with backticks (psql internal variable, not
#     shell expansion). The password flows through stdin, not process args.
#   - :'password' is psql's safe-quoting syntax (prevents SQL injection).
#   - SET log_statement = 'none' prevents the password from appearing in logs.
#   - The temp file is deleted after use.
#
# Note: psql does NOT perform -v variable substitution in -c command strings,
# only for SQL read from stdin or -f. Hence the heredoc.

set -eu

: "${API_DATABASE_PASSWORD:?API_DATABASE_PASSWORD must be set}"

PWFILE=/tmp/.pw_init_api
printf '%s' "$API_DATABASE_PASSWORD" > "$PWFILE"
chmod 600 "$PWFILE"

psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" \
     --dbname "$POSTGRES_DB" <<'SQL'
\set password `cat /tmp/.pw_init_api`
SET log_statement = 'none';
ALTER ROLE honeytrace_api PASSWORD :'password';
SET log_statement = 'ddl';
SQL

rm -f "$PWFILE"
