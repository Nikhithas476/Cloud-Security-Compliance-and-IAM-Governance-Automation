# REST API

`GET /health` is public. Every other endpoint requires `Authorization: Bearer <token>`.
`API_READER_TOKEN` grants read-only access; `API_OPERATOR_TOKEN` may start scans and request or
execute remediation; `API_REVIEWER_TOKEN` independently approves or rejects requests. Use three
separate random values from a secret manager and rotate them.

| Method and path | Minimum role | Result |
|---|---|---|
| `GET /health` | Public | Version and service health |
| `POST /scans` | Operator | Runs the existing multi-cloud workflow |
| `GET /scans/{scan_id}` | Reader | Stored scan metadata |
| `GET /findings` | Reader | Findings filtered by `provider`, `status`, and `limit` |
| `GET /findings/{finding_id}` | Reader | One sanitized finding |
| `GET /reports/{scan_id}` | Reader | Generated JSON, CSV and HTML report representations |
| `POST /remediation/{finding_id}` | Operator | Dry-run or already-approved controlled remediation |
| `POST /approvals/{finding_id}` | Operator | Create an exact, fingerprint-bound approval request |
| `GET /approvals/{approval_id}` | Reader | Read approval status |
| `POST /approvals/{approval_id}/approve` | Reviewer | Approve a pending request |
| `POST /approvals/{approval_id}/reject` | Reviewer | Reject a pending request |

Query limits are capped at 500. Finding evidence and resource metadata are deliberately excluded
from responses. Reports and approval state are persisted by the selected DynamoDB or Azure Blob
backend, so API and serverless processes can retrieve them across restarts.

A non-dry-run remediation requires a one-time `approval_id`. An operator creates the request and a
distinct reviewer approves it. It is bound to the exact finding, action, and parameters. The authenticated operator identity,
not a caller-provided actor, is written to the audit event. Put the API behind TLS, a rate-limiting
gateway/WAF, and private networking where possible.

Example remediation body:

```json
{
  "action": "azure.rbac.remove-assignment",
  "parameters": {
    "role_assignment_id": "/subscriptions/SUBSCRIPTION/providers/Microsoft.Authorization/roleAssignments/ASSIGNMENT"
  },
  "approval_id": "00000000-0000-4000-8000-000000000000",
  "dry_run": false
}
```

The body rejects extra fields. `401` means authentication failed, `403` means authorization or
approval failed, `404` means the requested record is absent, `422` means input validation failed,
and `500` responses are sanitized. Never send credentials or secrets as remediation parameters.
