-- Read-only export. Run with psql -X -qAt and explicit tenant_id/chat_id/from_utc/to_utc.
-- Moderator feedback supplies labels. Group repeated campaigns before splitting.
SELECT jsonb_build_object(
    'id', e.event_id,
    'label', CASE r.verdict WHEN 'KEEP' THEN 'ham' WHEN 'SPAM' THEN 'spam' ELSE 'unlabeled' END,
    'split', 'test',
    'campaign', '',
    'source', 'production',
    'evidence', snapshot - 'AuthorUsername' - 'Target' - 'Policy' - 'Profile'
)
FROM moderation_evidence e LEFT JOIN moderation_reviews r USING(event_id)
WHERE e.tenant_id = :'tenant_id'::uuid
  AND chat_id = :'chat_id'::bigint
  AND created_at >= :'from_utc'::timestamptz
  AND created_at < :'to_utc'::timestamptz
  AND expires_at > now()
ORDER BY created_at, e.event_id
LIMIT 5000;
