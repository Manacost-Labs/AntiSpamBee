-- +goose Up
CREATE TABLE moderation_operation_alerts (
    chat_id BIGINT NOT NULL,
    kind TEXT NOT NULL,
    next_available_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (chat_id, kind)
);

-- +goose Down
DROP TABLE moderation_operation_alerts;
