# DynamoDB storage schema

The DynamoDB implementation uses one table with string partition (`PK`) and sort (`SK`) keys.
It relies on boto3's standard credential chain and never accepts credential values.

| Record | PK | SK |
| --- | --- | --- |
| Finding | `FINDING#{finding_id}` | `METADATA` |
| Scan metadata | `SCAN#{scan_id}` | `METADATA` |
| Remediation history | `FINDING#{finding_id}` | `REMEDIATION#{created_at}#{action_id}` |

Findings also populate global secondary index `GSI1`:

- `GSI1PK = FINDINGS`
- `GSI1SK = {detected_at}#{finding_id}`

This supports reverse-chronological finding lists without a table scan. Provider and lifecycle
status are projected attributes used as optional query filters. The primary key supports direct
finding and scan retrieval, while remediation records colocated under a finding partition retain
chronological history. Applications should grant only the DynamoDB operations used here:
`PutItem`, `GetItem`, `UpdateItem`, and `Query` on the table and `GSI1`.
