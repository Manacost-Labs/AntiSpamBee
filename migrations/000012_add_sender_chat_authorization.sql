-- +goose Up
ALTER TABLE community_policies
    ADD COLUMN admin_sender_chat_id BIGINT NOT NULL DEFAULT 0;

UPDATE community_policies
SET admin_sender_chat_id = chat_id
WHERE admin_sender_chat_id = 0;

-- +goose Down
ALTER TABLE community_policies DROP COLUMN admin_sender_chat_id;
