#!/bin/sh
# Runs once, on first database initialization only (empty data volume).
# SQL init scripts cannot read environment variables, so the read-only role's
# password is set here instead.
#
# Note: psql does NOT perform -v variable substitution in -c command strings,
# only for SQL read from stdin or -f. Hence the heredoc.
set -eu

: "${API_DATABASE_PASSWORD:?API_DATABASE_PASSWORD must be set}"

psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" \
     --dbname "$POSTGRES_DB" \
     -v api_password="$API_DATABASE_PASSWORD" <<'SQL'
ALTER ROLE honeytrace_api PASSWORD :'api_password';
SQL
