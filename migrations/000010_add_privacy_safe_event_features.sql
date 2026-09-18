-- +goose Up
CREATE TABLE moderation_event_features (
    event_id UUID PRIMARY KEY REFERENCES moderation_events(event_id) ON DELETE CASCADE,
    update_kind TEXT NOT NULL DEFAULT 'unknown',
    text_length INTEGER NOT NULL DEFAULT 0 CHECK (text_length >= 0),
    ocr_text_length INTEGER NOT NULL DEFAULT 0 CHECK (ocr_text_length >= 0),
    has_link BOOLEAN NOT NULL DEFAULT FALSE,
    media_types TEXT[] NOT NULL DEFAULT '{}',
    content_fingerprint TEXT NOT NULL DEFAULT ''
);

CREATE INDEX moderation_event_features_media_idx
    ON moderation_event_features (update_kind)
    WHERE cardinality(media_types) > 0;

-- +goose Down
DROP TABLE moderation_event_features;
