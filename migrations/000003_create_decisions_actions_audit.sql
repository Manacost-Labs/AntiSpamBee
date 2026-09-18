-- +goose Up
ALTER TABLE moderation_events
    DROP CONSTRAINT moderation_events_terminal_state_check;

ALTER TABLE moderation_events
    ADD CONSTRAINT moderation_events_terminal_state_check CHECK (
        terminal_state IN (
            'DECIDED_PENDING_ACTION',
            'PROCESSED_ALLOW',
            'PROCESSED_ACTION',
            'PROCESSED_REVIEW',
            'IGNORED_BY_POLICY',
            'INVALID',
            'DEAD_LETTER'
        )
    );

CREATE TABLE moderation_decisions (
    decision_id UUID PRIMARY KEY,
    event_id UUID NOT NULL UNIQUE REFERENCES moderation_events(event_id) ON DELETE CASCADE,
    risk_score NUMERIC(4, 3) NOT NULL CHECK (risk_score BETWEEN 0 AND 1),
    decision_confidence NUMERIC(4, 3) NOT NULL CHECK (decision_confidence BETWEEN 0 AND 1),
    evidence_coverage NUMERIC(4, 3) NOT NULL CHECK (evidence_coverage BETWEEN 0 AND 1),
    recommended_action TEXT NOT NULL,
    authorized_action TEXT NOT NULL,
    authorization_reason TEXT NOT NULL,
    decision_version TEXT NOT NULL DEFAULT 'decision-v1',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE moderation_actions (
    action_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    decision_id UUID NOT NULL REFERENCES moderation_decisions(decision_id) ON DELETE CASCADE,
    event_id UUID NOT NULL REFERENCES moderation_events(event_id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    action_type TEXT NOT NULL CHECK (
        action_type IN ('DELETE_MESSAGE', 'DELETE_REACTION', 'BAN_USER')
    ),
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (
        status IN ('PENDING', 'CLAIMED', 'RETRYABLE', 'SUCCEEDED', 'SUCCEEDED_ASSUMED', 'PERMANENT_FAILED', 'CANCELLED')
    ),
    chat_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    message_id BIGINT NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    lease_owner TEXT,
    lease_until TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX moderation_actions_claim_idx
    ON moderation_actions (next_attempt_at, created_at)
    WHERE status IN ('PENDING', 'RETRYABLE', 'CLAIMED');

CREATE TABLE moderation_audit_log (
    audit_id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL,
    event_id UUID REFERENCES moderation_events(event_id) ON DELETE SET NULL,
    action_id UUID REFERENCES moderation_actions(action_id) ON DELETE SET NULL,
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (event_id, actor_type, actor_id, operation)
);

CREATE INDEX moderation_audit_tenant_created_idx
    ON moderation_audit_log (tenant_id, created_at DESC);

-- +goose Down
DROP TABLE moderation_audit_log;
DROP TABLE moderation_actions;
DROP TABLE moderation_decisions;

ALTER TABLE moderation_events
    DROP CONSTRAINT moderation_events_terminal_state_check;

ALTER TABLE moderation_events
    ADD CONSTRAINT moderation_events_terminal_state_check CHECK (
        terminal_state IN (
            'PROCESSED_ALLOW',
            'PROCESSED_ACTION',
            'PROCESSED_REVIEW',
            'IGNORED_BY_POLICY',
            'INVALID',
            'DEAD_LETTER'
        )
    );
