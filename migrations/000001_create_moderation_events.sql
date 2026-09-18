-- +goose Up
CREATE TABLE moderation_events (
    event_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    source_key TEXT NOT NULL UNIQUE,
    bot_id BIGINT NOT NULL CHECK (bot_id > 0),
    telegram_update_id BIGINT NOT NULL CHECK (telegram_update_id > 0),
    schema_version TEXT NOT NULL,
    terminal_state TEXT NOT NULL CHECK (
        terminal_state IN (
            'PROCESSED_ALLOW',
            'PROCESSED_ACTION',
            'PROCESSED_REVIEW',
            'IGNORED_BY_POLICY',
            'INVALID',
            'DEAD_LETTER'
        )
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    processed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (bot_id, telegram_update_id)
);

CREATE INDEX moderation_events_tenant_created_idx
    ON moderation_events (tenant_id, created_at DESC);

-- +goose Down
DROP TABLE moderation_events;
