# Optional GitHub Check consumer

`github_check.py` is a separate, one-shot consumer. Core never imports, launches
or waits for it. It calls only the trusted Core's read-only `report-verify`, then
maps the existing decision to an **already provisioned** GitHub Check. It does
not execute checks, create commits/PRs, manage rules, observe merges or schedule
work. The migrated implementation preserves the independently tested Core result-consumer contract.

Use a consumer account/environment that cannot be accessed by workload code.
Keep its token, configuration and SQLite state outside candidate and evidence
directories. The state database has one owner for each Check; multiple machines
with independent state databases are unsupported. Core receives a minimal child
environment without the consumer token.

## Independently trusted configuration

The configuration is an operator-owned JSON object, not an incoming event or a
file supplied by the candidate. It records an independently reviewed association
between the target Git SHA and the exact current result. Do not produce approval
by copying fields from an arbitrary report. Required fields are:

- `repository`, `target_sha`, `check_id`, `check_name`, `app_id`: the existing
  remote Check and its expected repository, SHA, name and GitHub App identity.
- `generation`: a positive, strictly increasing mapping revision for that Check.
- `expires_at`: timezone-qualified expiry of the current-use review.
- `current_use_review`: exactly `approved-exact-result`, supplied only after
  independently checking candidate/target, baseline, policy, tools, execution
  environment and evidence applicability.
- `verifier_sha256`: digest of the trusted absolute Core executable used to read
  saved evidence. Protect that executable from replacement during use.
- `machine_sha256`, `manifest_sha256`, `invocation_id`: current reviewed evidence
  pins, using the existing saved-report contract.
- `source_identity`, `configuration_digest`, `profile`,
  `verification_policy_identity`, `quality_policy_identity`,
  `runtime_bundle_digest`: exact expected existing result fields.

The machine digest binds the entire result, including its baseline and coverage.
The reader verifies the saved evidence and preserves the historical decision.
The consumer compares the independent pins; it never recomputes thresholds,
requiredness or waivers. For success it additionally requires complete evidence,
a compiled policy binding and the Core's completed full-quality success. Partial,
unexecuted or unapproved results are rejected, never mapped to neutral/skipped.
Core's `not_proven` field is not changed or treated as host attestation. If the
operator cannot establish current applicability, no approval should be issued.

Preview performs evidence reading and mapping only:

```sh
python3 github_check.py \
  --core /protected/bin/harness-gate \
  --config /protected/consumer/current-use.json \
  --index /protected/evidence/index.json
```

Add `--apply --state /protected/consumer/checks.sqlite` to send the mapping.
Only this separate consumer receives `GATEHOUSE_CHECK_TOKEN`, with the appropriate
GitHub Check write permission. Branch protection and required App/name selection
remain GitHub/user configuration. API behavior follows the
[Check runs API](https://docs.github.com/en/rest/checks/runs).

## Ordering, errors and retries

Before updating, the consumer reads and validates the remote Check identity.
It durably records intent before sending PATCH. A confirmed identical event is
deduplicated; conflicting duplicates and older generations reject. Newer
generations are admitted only after the previous operation is confirmed.

A preflight failure makes no mutation and may be retried. Once an API mutation
has been attempted, transport failure, malformed replies or process interruption
leave an uncertain intent. Subsequent requests refuse to write through it.
An API timeout does not prove the request was not applied: blindly retrying and
then accepting a newer revision can let the original delayed request overwrite
the newer result. Reconciliation therefore requires the consumer operator to
establish that no prior request remains in flight before repairing state. There
is intentionally no automatic state-reset or retry-through-uncertainty command.

For an independently determined applicability failure, use `--withdraw` with a
newer generation, `current_use_review = "withdrawn"`, a bounded
`withdrawal_reason`, and the same target/Check/App fields and approval expiry.
No `--core` or `--index` is used: withdrawal updates only the platform Check to
failure with an explicit applicability explanation. It neither reads nor edits
the historical quality decision. Preview is still the default; `--apply` uses
the same durable ordering and uncertainty protections as result mapping.

Transport failure changes only consumer state and its exit status. It never
modifies the saved report, reruns Core verification, or changes the historical
quality conclusion. Rejected evidence produces no remote update; it does not
implicitly revoke an earlier Check. Withdrawal requires the explicit independently
authorized consumer configuration above. Provisioning a Check and configuring
required App/name remain with the consumer owner; this tool updates only the
given Check. Release acceptance exercises the extracted consumer against a pinned released Core and fake API; no live API mutation is needed.

## Distribution

The independent `github-check-v1.0.0` archive contains this program, documentation, identity manifest and license. Python 3.11+ is required. Verify its checksums and repository workflow provenance before extraction; run `python3 github_check.py --help` inside the extracted directory. The Core executable is supplied separately and pinned by the operator. This is an external result consumer, not a Core measurement plugin or preset; Core never installs or invokes it.
