-- +goose Up
CREATE TABLE moderation_evidence (
    event_id UUID PRIMARY KEY REFERENCES moderation_events(event_id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL,
    chat_id BIGINT NOT NULL,
    message_id BIGINT NOT NULL,
    snapshot JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '30 days'
);
CREATE INDEX moderation_evidence_chat_idx ON moderation_evidence(tenant_id, chat_id, created_at DESC);
CREATE INDEX moderation_evidence_expiry_idx ON moderation_evidence(expires_at);

CREATE TABLE moderation_notification_outbox (
    action_id UUID PRIMARY KEY REFERENCES moderation_actions(action_id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL,
    community_chat_id BIGINT NOT NULL,
    payload JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING','CLAIMED','RETRYABLE','SENT','FAILED','CANCELLED')),
    attempts INTEGER NOT NULL DEFAULT 0,
    lease_owner TEXT,
    lease_until TIMESTAMPTZ,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '30 days'
);
CREATE INDEX moderation_notification_due_idx ON moderation_notification_outbox(next_attempt_at) WHERE status IN ('PENDING','RETRYABLE','CLAIMED');
CREATE INDEX moderation_notification_expiry_idx ON moderation_notification_outbox(expires_at);

-- +goose Down
DROP TABLE moderation_notification_outbox;
DROP TABLE moderation_evidence;
