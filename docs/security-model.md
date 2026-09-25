# Security model

Protected assets are cloud inventory, findings, identifiers, reports, approvals, audit history and
credentials. Untrusted inputs include API values, YAML rules, provider responses, webhook responses
and deployment parameters.

| Threat | Mitigation |
|---|---|
| Credential disclosure | Standard identity chains, OIDC/managed identity, ignored secrets, no body logging |
| Unauthorized mutation | Operator request plus independent reviewer approval; scanners have no mutation path |
| Approval replay/substitution | Atomic consumption and binding to finding, action and parameters |
| Cloud failure/blast radius | Independent adapters, identities and partial-failure isolation |
| Invalid or sensitive data | Strict bounded schemas, safe exceptions and response allowlists |
| Audit loss | Structured persistent events, DynamoDB PITR/Azure Blob versioning and CloudTrail validation |
| Supply-chain/IaC regression | Locks, pip-audit, Bandit, Gitleaks, Checkov, Terraform and cfn-lint gates |

Finding evidence/resource metadata are excluded from public API responses. Residual deployer duties
include private endpoints/DNS, gateway TLS/rate limits/WAF, secret rotation, encrypted remote state,
signed packages, log access/retention and reviewer separation. See [security-review.md](security-review.md).
