-- Read-only export. Run with psql -X -qAt and explicit tenant_id/chat_id/from_utc/to_utc.
-- Labels/campaigns require human review; machine decisions are never labels.
SELECT jsonb_build_object(
    'id', event_id,
    'label', 'unlabeled',
    'split', 'test',
    'campaign', '',
    'source', 'production',
    'evidence', snapshot - 'AuthorUsername' - 'Target' - 'Policy' - 'Profile'
)
FROM moderation_evidence
WHERE tenant_id = :'tenant_id'::uuid
  AND chat_id = :'chat_id'::bigint
  AND created_at >= :'from_utc'::timestamptz
  AND created_at < :'to_utc'::timestamptz
  AND expires_at > now()
ORDER BY created_at, event_id
LIMIT 5000;
