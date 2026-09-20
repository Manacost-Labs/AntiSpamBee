# Production hardening — first increment (2026-09-20)

## Scope and invariant

Policy `message-evidence-v2` never queues an automatic ban. Only high-confidence
evidence from the current message can authorize automatic deletion. Profile-only,
behavior-only, reaction-only, or unavailable-message cases remain reviewable.
This is intentionally conservative: profile-driven spam and flood can require
manual handling until the corresponding measured policies are introduced.

The evidence snapshot and decision/action are committed together. Successful
deletion and its notification outbox entry are committed together. Delivery
retries cannot re-delete the message. Evidence reads and delivery require current
administrator privileges, plus the saved group binding.

## Verification

- Unit regressions: profile-only ban, model without message, historical risk,
  correlated signals, explicit-message deletion, profile isolation from JEV.
- Worker regressions: Telegram 429 followed by success without another delete;
  revoked admin receives no content.
- Real PostgreSQL integration: archive survives deletion; one outbox entry;
  exclusive lease, expired lease recovery, rejection of stale completion;
  tenant isolation, expiry filtering and physical cleanup.
- Full Go tests with race detector using isolated PostgreSQL, go vet, targeted
  codex-semgrep, and migration application on an empty database.

The production policy is stricter, not a measured precision improvement yet.
No synthetic advertising messages, deletes or bans are sent to real groups for tests.

## Release and rollback

1. Back up PostgreSQL and retain currently running image IDs.
2. Build the new images before interrupting workers. Check pending old actions.
3. Pause moderation/action workers, apply additive migration 000013, start new
   workers. Gateway continues durably queueing incoming updates.
4. Verify readiness, version 000013, worker logs, outbox age/status and archive.
5. Update Telegram command menu. Verify history with an actual admin on real use.

Keep the new tables on rollback. Their Down migration deletes evidence and must
not be used against production data as an ordinary rollback. Rolling back the
binary to the previous policy restores unsafe automatic bans: prefer pausing
workers and a forward fix, or set affected groups to OBSERVE before reverting.
No code rollback can restore a deleted Telegram message.

Content retention is 30 days in live storage; backup retention and access must
be handled separately. Backups and env files are excluded from Docker build/Git.

## Remaining roadmap

1. Full interactive admin cabinet, scoped callback authorization and revocable
   channel bindings; feedback and explicitly confirmed violations.
2. Labeled validation data, campaign/time splits, precision/recall and uncertainty;
   no acceptance based solely on deletion counts or green health probes.
3. Evidence-strength validation, similar campaigns and selective image models.
4. Bounded concurrency, queue-age metrics/alerts, cancellation/drain failure tests,
   supported Go toolchain upgrade as an independent release.
5. Shadow evaluation and cohort rollout for any expansion of automatic actions.

The first increment does not implement these remaining items or claim 99% accuracy.
