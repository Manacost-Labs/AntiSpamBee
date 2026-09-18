-- +goose Up
ALTER TABLE moderation_actions
    DROP CONSTRAINT moderation_actions_event_id_key;

-- +goose Down
ALTER TABLE moderation_actions
    ADD CONSTRAINT moderation_actions_event_id_key UNIQUE (event_id);
