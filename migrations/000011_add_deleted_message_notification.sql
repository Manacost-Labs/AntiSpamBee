-- +goose Up
ALTER TABLE moderation_actions
    ADD COLUMN notification_chat_id BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN notification_author_username TEXT NOT NULL DEFAULT '',
    ADD COLUMN notification_author_user_id BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN notification_message TEXT NOT NULL DEFAULT '',
    ADD COLUMN notification_reasons TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN notification_risk_score DOUBLE PRECISION NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE moderation_actions
    DROP COLUMN notification_risk_score,
    DROP COLUMN notification_reasons,
    DROP COLUMN notification_message,
    DROP COLUMN notification_author_user_id,
    DROP COLUMN notification_author_username,
    DROP COLUMN notification_chat_id;
