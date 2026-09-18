#!/bin/sh
set -eu

psql "$DATABASE_URL" --set ON_ERROR_STOP=1 <<'SQL'
CREATE TABLE IF NOT EXISTS schema_migrations (
    filename TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
SQL

for migration in /migrations/*.sql; do
    filename=$(basename "$migration")
    applied=$(psql "$DATABASE_URL" -tAc "SELECT 1 FROM schema_migrations WHERE filename = '$filename'")
    if [ "$applied" = "1" ]; then
        continue
    fi
    {
        echo 'BEGIN;'
        sed '/^-- +goose Down$/,$d' "$migration"
        printf "INSERT INTO schema_migrations (filename) VALUES ('%s');\n" "$filename"
        echo 'COMMIT;'
    } | psql "$DATABASE_URL" --set ON_ERROR_STOP=1
done
