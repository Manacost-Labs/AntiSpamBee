-- +goose Up
ALTER TABLE moderation_actions
    DROP CONSTRAINT moderation_actions_action_type_check;

ALTER TABLE moderation_actions
    ADD CONSTRAINT moderation_actions_action_type_check CHECK (
        action_type IN ('DELETE_MESSAGE', 'DELETE_REACTION', 'BAN_USER', 'MUTE_USER', 'UNBAN_USER')
    );

-- +goose Down
ALTER TABLE moderation_actions
    DROP CONSTRAINT moderation_actions_action_type_check;

ALTER TABLE moderation_actions
    ADD CONSTRAINT moderation_actions_action_type_check CHECK (
        action_type IN ('DELETE_MESSAGE', 'DELETE_REACTION', 'BAN_USER', 'MUTE_USER')
    );
