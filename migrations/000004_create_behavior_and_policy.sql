-- +goose Up
CREATE TABLE message_activity (
    event_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    chat_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    message_id BIGINT NOT NULL,
    content_fingerprint TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX message_activity_flood_idx
    ON message_activity (tenant_id, chat_id, user_id, observed_at DESC);

CREATE INDEX message_activity_duplicate_idx
    ON message_activity (tenant_id, chat_id, content_fingerprint, observed_at DESC);

CREATE TABLE community_policies (
    tenant_id UUID NOT NULL,
    chat_id BIGINT NOT NULL,
    protection_level TEXT NOT NULL DEFAULT 'STANDARD' CHECK (
        protection_level IN ('OBSERVE', 'SOFT', 'STANDARD', 'STRICT')
    ),
    automatic_actions_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    moderator_chat_id BIGINT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, chat_id)
);

CREATE TABLE moderation_allowlist (
    tenant_id UUID NOT NULL,
    chat_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    added_by BIGINT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, chat_id, user_id)
);

CREATE TABLE user_reports (
    report_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    chat_id BIGINT NOT NULL,
    reporter_user_id BIGINT NOT NULL,
    reported_user_id BIGINT NOT NULL,
    message_id BIGINT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'RESOLVED', 'DISMISSED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, chat_id, reporter_user_id, message_id)
);

-- +goose Down
DROP TABLE user_reports;
DROP TABLE moderation_allowlist;
DROP TABLE community_policies;
DROP TABLE message_activity;
