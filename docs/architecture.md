# Architecture

Cloud-specific scanners are read-only adapters. Everything after normalization is provider-neutral.
Expected failure in one cloud does not discard successful results from the other.

```mermaid
flowchart LR
  AWS[AWS: IAM · Encryption · Trail · Config]
  AZ[Azure: RBAC · Policy · Storage · Defender]
  ORCH[ScannerOrchestrator]
  FIND[Normalized Findings]
  COMP[ComplianceEngine]
  RISK[RiskCalculator]
  STORE[(DynamoDB)]
  REPORT[JSON · CSV · HTML]
  ALERT[HTTPS Webhook]
  AWS --> ORCH
  AZ --> ORCH
  ORCH --> FIND
  FIND --> COMP
  FIND --> RISK
  FIND --> STORE
  COMP --> REPORT
  RISK --> REPORT
  FIND --> ALERT
```

`ComplianceWorkflowService` owns the sequence. FastAPI, Lambda and Azure Functions validate
transport input, enforce access control and delegate. Reports and alerts use allowlisted fields.

## Remediation boundary

```mermaid
sequenceDiagram
  participant O as Operator
  participant E as RemediationEngine
  participant A as ApprovalService
  participant C as Cloud API
  participant L as Audit sink
  O->>E: Review finding and exact parameters
  E->>C: Read current state
  E->>A: Create fingerprint-bound request
  Note over A: Explicit approval
  O->>E: Execute with approval ID
  E->>A: Consume one-use approval
  E->>C: Controlled mutation
  E->>C: Verify state
  E->>L: Append result and before/after state
```

Dry runs stop after review. Invalid, mismatched and replayed approvals never mutate cloud state and
are still audited. AWS and Azure use separate scan/remediation identities. DynamoDB details are in
[dynamodb-schema.md](dynamodb-schema.md); deployment boundaries are in the infrastructure guide.
