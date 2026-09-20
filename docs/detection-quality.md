# Detection quality: evidence and evaluation

## Shipped code, not an accuracy claim

`message-evidence-v3` keeps automatic bans paused. Model-based deletion needs
the existing risk/category confidence thresholds **and** evidence strength >=1.8
on the API's 0..2 scale, evidence confidence >=0.90, a non-`none` category, and
a selected literal source passage with confidence >=0.90. These are conservative
engineering thresholds, not calibrated probabilities of correctness.

The model selects one of at most 32 source passages (400 Unicode characters each).
Unknown/missing passage IDs cannot become evidence. Excerpts are stored in the
30-day audit and shown in `/history`. A real quote still does **not** prove that
the model interpreted it correctly. Additional passage context increases model
input and may affect latency/cost; measure before expanding the request further.

Keyword matches in recognizable scam warnings/quoted-spam discussions remain
reviewable but cannot independently authorize deletion. This is not a blanket
allowlist: a model can still identify active promotion in such messages. Warnings
not covered by these patterns can still cause false positives. New recall rules
must be evaluated offline before enabling automatic actions.

Five messages in a short window alone now give moderate, not high, behavioral
risk. Duplicate content remains a separate signal. The audit records duplicate,
frequency and previous-violation counts. These are suspicions of spam behavior,
not proof that a human-looking account is automated. No bot-identification accuracy
is claimed, and behavior alone cannot delete a message or ban an account.

## Independent real-message sample

The processor deterministically samples approximately 5% of message events,
independently of their score/action, and marks `EvaluationSample=true`. It also
keeps all non-ALLOW audit cases as before. Both expire after 30 days using the
existing bounded purge. ALLOW samples do not appear in the admin decision history
and do not create notifications or actions. Existing backups have separate retention.

This enables missed-spam measurement; deletion-only audits cannot measure recall.
The sample unit is an event, so edited messages can appear more than once. Group
edits/duplicates/campaign variants together during labeling and splitting. At low
message volumes the 5% sample may be too small; do not infer safety from silence.

## Export and human labels

`scripts/export-evaluation.sql` is read-only and requires explicit `tenant_id`,
`chat_id`, `from_utc`, and `to_utc` psql variables. Use `psql -X -qAt --set ON_ERROR_STOP=1`.
Export to `data/evaluation-private/` with `umask 077`; never commit real messages.
That directory is excluded from git and Docker context. The export strips direct
author/group metadata but message text can still contain personal information.
Do not upload it elsewhere. Remove local exports when their retention period ends.

Before evaluation, a human must fill these fields on every JSONL row:

- `label`: `spam`, `ham`, or `uncertain` according to the group's written rules.
- `campaign`: shared identifier for duplicates/edits/variants of the same campaign.
- `split`: `dev` for rule development or `test` for held-out evaluation.

Label text without looking at the old model score/action. Review disagreements
separately; do not turn a previous deletion into a positive label. Keep later time
periods for testing and never split a campaign across dev/test. The runner rejects
campaign leakage, duplicate IDs, missing labels, truncated evidence and mixed
synthetic/production data. Export is limited to 5000 rows: use explicit time
windows and check completeness if this limit is reached.

## Offline comparison, no Telegram actions

```sh
go run ./cmd/moderation-eval -input internal/evaluation/testdata/synthetic.jsonl
go run ./cmd/moderation-eval -input data/evaluation-private/labeled.jsonl -representative -mode replay
```

`rules` runs the current message rules. `replay` additionally uses saved v3 model
responses and re-evaluates saved behavioral counts. It makes no model/API calls
and does not evaluate a changed model/prompt: that needs new responses. Old model
versions are rejected rather than silently treated as current. `ModelAvailable`
shows model coverage. Admin exemptions are intentionally not applied: this measures
content detection, not policy execution. Profile context is not evaluated here.

For representative production metrics use `-representative`; otherwise the enriched
audit dataset overrepresents suspicious messages. The report includes TP/FP/TN/FN,
false-positive/negative IDs, review count, precision, recall and the Wilson 95%
lower precision bound. Zero-denominator metrics are null. REVIEW counts as not
automatically removed, and uncertain labels are excluded and reported separately.
Wilson bounds assume independent examples; clustered campaigns weaken that
assumption, so also inspect results by campaign/time period. Never use synthetic
results as a production accuracy estimate.

The 16-row seed corpus is synthetic regression protection: six spam examples,
nine benign examples and one uncertain case. It is deliberately small, has no
independent holdout (it was used while developing these rules), and is insufficient
for launch-quality estimates. The remaining release gate is human-labeled real
data, sufficient sample size, and a before/after comparison of both false removals
and missed spam. Do not enable auto-bans based on this seed corpus.
