# Remediation

Every action follows Finding → Review → Approval → Remediation → Verification. `review_and_request`
reads current state and fingerprints the finding ID, action and exact parameters. A reviewer approves
or rejects it. The engine consumes an approval once before mutation; replay or parameter substitution
fails.

- `aws.iam.disable-stale-access-key`: deactivate one key and read it back
- `aws.iam.remove-policy-permission`: remove one exact Action/Resource value via a new managed-policy version
- `azure.rbac.remove-assignment`: delete one exact assignment and verify absence

Dry run only reviews. Scanning never remediates. Every attempt records finding, action, actor,
timestamp, outcome, approval ID and before/after state; `StorageAuditSink` persists this history.
Production requires separate reviewers/operators and narrowly scoped cloud identities.
