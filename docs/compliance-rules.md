# Compliance rules

`config/rules.yaml` is validated. Each rule has an ID, name, cloud, severity, description, enabled
flag and remediation-availability flag. IDs are lowercase, cloud-prefixed, unique, and may only use
a trailing `.*` wildcard. The engine matches normalized findings; it never repeats cloud logic.

AWS rules cover IAM wildcard actions/resources, MFA, stale/root keys, S3/EBS encryption, CloudTrail,
Config recorder state and selected Config-rule compliance. Azure rules cover privileged/excessive
RBAC, Policy violations, Storage service/infrastructure/CMK encryption and Defender recommendations.

Severity feeds configurable risk weights. `remediation_available` is descriptive and never grants
authorization. Executable actions remain limited to an exact stale key, exact customer-managed IAM
policy permission, or exact Azure RBAC assignment.

| Rule ID | Default severity |
|---|---|
| `aws.iam.policy.wildcard-action` | Critical |
| `aws.iam.policy.wildcard-resource` | High |
| `aws.iam.user.mfa-enabled` | High |
| `aws.iam.access-key.stale` | High |
| `aws.iam.root.access-key` | Critical |
| `aws.s3.bucket.encryption-enabled` | High |
| `aws.ec2.ebs.volume-encryption-enabled` | High |
| `aws.cloudtrail.trail.exists` | Critical |
| `aws.cloudtrail.logging.enabled` | Critical |
| `aws.config.recorder.enabled` | High |
| `aws.config.rule.compliant` | High |
| `azure.rbac.owner-assignment` | Critical |
| `azure.rbac.contributor-assignment` | High |
| `azure.rbac.subscription-privileged-assignment` | Critical |
| `azure.rbac.excessive-permissions` | High |
| `azure.policy.non-compliant-resource` | High |
| `azure.storage.encryption.service-enabled` | High |
| `azure.storage.encryption.infrastructure-enabled` | Medium |
| `azure.storage.encryption.customer-managed-key` | High |
| `azure.defender.recommendation.*` | Finding-specific; template defaults informational |
