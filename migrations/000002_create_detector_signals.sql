-- +goose Up
CREATE TABLE detector_signals (
    event_id UUID NOT NULL REFERENCES moderation_events(event_id) ON DELETE CASCADE,
    schema_version TEXT NOT NULL,
    detector TEXT NOT NULL,
    detector_version TEXT NOT NULL,
    category TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('AVAILABLE', 'MISSING', 'ERROR', 'STALE', 'NOT_SUPPORTED', 'PRIVATE')
    ),
    score NUMERIC(4, 3) CHECK (score BETWEEN 0 AND 1),
    confidence NUMERIC(4, 3) CHECK (confidence BETWEEN 0 AND 1),
    severity TEXT NOT NULL CHECK (
        severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
    ),
    evidence_coverage NUMERIC(4, 3) NOT NULL CHECK (evidence_coverage BETWEEN 0 AND 1),
    reason_codes TEXT[] NOT NULL,
    matched_rules TEXT[] NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (event_id, detector, detector_version),
    CHECK (
        (status = 'AVAILABLE' AND score IS NOT NULL AND confidence IS NOT NULL)
        OR
        (status <> 'AVAILABLE' AND score IS NULL AND confidence IS NULL)
    )
);

CREATE INDEX detector_signals_category_score_idx
    ON detector_signals (category, score DESC)
    WHERE status = 'AVAILABLE';

-- +goose Down
DROP TABLE detector_signals;
