-- +goose Up
ALTER TABLE moderation_actions ADD COLUMN manual_review BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE moderation_command_reply_outbox DROP CONSTRAINT moderation_command_reply_outbox_event_id_fkey;
ALTER TABLE moderation_command_reply_outbox ADD CONSTRAINT moderation_command_reply_outbox_event_id_fkey
    FOREIGN KEY (event_id) REFERENCES moderation_events(event_id) ON DELETE CASCADE;

CREATE TABLE moderation_reviews (
    event_id UUID PRIMARY KEY REFERENCES moderation_evidence(event_id) ON DELETE CASCADE,
    verdict TEXT CHECK (verdict IN ('KEEP', 'SPAM')),
    reviewer_id BIGINT,
    reviewed_at TIMESTAMPTZ,
    CHECK ((verdict IS NULL AND reviewer_id IS NULL AND reviewed_at IS NULL)
        OR (verdict IS NOT NULL AND reviewer_id > 0 AND reviewed_at IS NOT NULL))
);

CREATE TABLE moderation_campaign_observations (
    tenant_id UUID NOT NULL,
    chat_id BIGINT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('contact', 'link', 'image')),
    fingerprint BYTEA NOT NULL,
    user_id BIGINT NOT NULL CHECK (user_id > 0),
    message_id BIGINT NOT NULL CHECK (message_id > 0),
    confirmed_advertising BOOLEAN NOT NULL DEFAULT FALSE,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, chat_id, kind, fingerprint, message_id)
);
CREATE INDEX moderation_campaign_observed_idx ON moderation_campaign_observations(observed_at);

-- +goose Down
DELETE FROM moderation_command_reply_outbox outbox WHERE NOT EXISTS (
    SELECT 1 FROM moderation_command_commits command WHERE command.event_id = outbox.event_id
);
ALTER TABLE moderation_command_reply_outbox DROP CONSTRAINT moderation_command_reply_outbox_event_id_fkey;
ALTER TABLE moderation_command_reply_outbox ADD CONSTRAINT moderation_command_reply_outbox_event_id_fkey
    FOREIGN KEY (event_id) REFERENCES moderation_command_commits(event_id) ON DELETE CASCADE;
DROP TABLE moderation_campaign_observations;
DROP TABLE moderation_reviews;
ALTER TABLE moderation_actions DROP COLUMN manual_review;
