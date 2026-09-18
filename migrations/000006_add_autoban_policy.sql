-- +goose Up
ALTER TABLE community_policies
    ADD COLUMN autoban_enabled BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE community_policies
    ALTER COLUMN protection_level SET DEFAULT 'STRICT';

UPDATE community_policies
SET
    automatic_actions_enabled = protection_level IN ('STANDARD', 'STRICT'),
    autoban_enabled = protection_level = 'STRICT';

-- +goose Down
ALTER TABLE community_policies DROP COLUMN autoban_enabled;
ALTER TABLE community_policies ALTER COLUMN protection_level SET DEFAULT 'STANDARD';
