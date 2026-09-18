#!/bin/sh
set -eu

for migration in /migrations/*.sql; do
    sed '/^-- +goose Down$/,$d' "$migration" \
        | psql --set ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB"
done
