# Security review

Review completed across application and deployment surfaces.

- AWS scanning and remediation use separate roles. Scan access is read-only; mutations are limited
  to access-key status and customer-managed policy versions. DynamoDB is encrypted with PITR.
- Azure uses separate scan/remediation managed identities, TLS 1.2, disabled public blob access,
  Reader/Security Reader for scans, and a custom remediation role limited to RBAC assignment
  read/delete. No client secret is embedded in infrastructure.
- API tokens come only from runtime secrets, are compared in constant time, and map to reader or
  operator roles. Remediation additionally requires a matching, one-use explicit approval.
- Public finding responses omit arbitrary evidence/metadata. Logs record identifiers and exception
  classes, never request bodies, tokens, exception messages, policy documents, or credentials.
- Pydantic rejects extra remediation fields, validates UUIDs/action names, and caps list sizes.
- CloudTrail has log validation; its bucket blocks public access and non-TLS requests. AWS Config is
  enabled by Terraform. CI fails on lint, tests, coverage, dependency audit, Bandit, Gitleaks,
  Checkov, Terraform validation, and CloudFormation lint.
- Deployments are manual, protected-environment jobs using GitHub OIDC. No long-lived cloud keys are
  required. Generated plans, state, reports and scan results are ignored.

Residual deployment responsibilities: configure remote Terraform state, Azure private endpoints and
DNS, API gateway rate limits, secret rotation, immutable package signing, alert destinations, and
organization-specific resource scopes. Review every plan/change set and provider release before use.
