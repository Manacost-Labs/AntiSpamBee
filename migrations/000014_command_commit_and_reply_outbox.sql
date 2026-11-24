-- +goose Up
CREATE TABLE moderation_command_commits (
    event_id UUID PRIMARY KEY REFERENCES moderation_events(event_id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE moderation_command_reply_outbox (
    reply_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID NOT NULL REFERENCES moderation_command_commits(event_id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    payload JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING','CLAIMED','RETRYABLE','SENT','FAILED')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    lease_owner TEXT,
    lease_until TIMESTAMPTZ,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '30 days',
    UNIQUE (event_id, ordinal)
);
CREATE INDEX moderation_command_reply_due_idx ON moderation_command_reply_outbox(next_attempt_at,created_at)
    WHERE status IN ('PENDING','RETRYABLE','CLAIMED');
CREATE INDEX moderation_command_reply_expiry_idx ON moderation_command_reply_outbox(expires_at);

-- +goose Down
DROP TABLE moderation_command_reply_outbox;
DROP TABLE moderation_command_commits;
