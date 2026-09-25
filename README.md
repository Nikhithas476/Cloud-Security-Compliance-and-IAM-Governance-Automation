# Cloud Security Compliance and IAM Governance Automation

A portfolio-ready Python security platform that scans AWS and Azure, normalizes findings, evaluates
configuration-driven controls, calculates deterministic risk, stores results, generates audit-ready
reports, sends high-risk alerts, and performs explicitly approved remediations.

## Capabilities

- AWS: IAM wildcard policies, missing MFA, stale/root keys, S3/EBS encryption, CloudTrail and Config
- Azure: privileged/excessive RBAC, Policy, Storage encryption and Defender recommendations
- Pydantic models, multi-cloud failure isolation, compliance, risk, DynamoDB, reports and webhooks
- Review → approval → remediation → verification with one-use approvals, dry runs and audit history
- Authenticated FastAPI, AWS Lambda/Azure Functions, Terraform, CloudFormation and OIDC CI/CD

## Quick start

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
$env:API_READER_TOKEN = "generate-a-distinct-random-value-at-least-32-characters"
$env:API_OPERATOR_TOKEN = "generate-another-random-value-at-least-32-characters"
$env:API_REVIEWER_TOKEN = "generate-an-independent-random-value-at-least-32-characters"
uvicorn cloud_security_governance.main:app --app-dir src --host 127.0.0.1 --port 8000
```

`GET /health` is public. Other routes require a bearer token. The application does not auto-load
`.env`; use workload identity, managed identity or a deployment secret manager.

## Validate and demonstrate

```powershell
./scripts/test.ps1
.venv\Scripts\python.exe scripts/portfolio_demo.py
```

The validation script runs formatting, linting, coverage, security and infrastructure checks. The
offline demonstration writes sanitized artifacts to ignored `demo-output/`.

## Documentation

- [Architecture](docs/architecture.md)
- [Setup](docs/setup.md)
- [Security model](docs/security-model.md) and [security review](docs/security-review.md)
- [Compliance rules](docs/compliance-rules.md), [risk](docs/risk-scoring.md) and [remediation](docs/remediation.md)
- [REST API](docs/api.md), [deployment](infrastructure/README.md) and [portfolio demo](docs/portfolio-demo.md)
- [DynamoDB schema](docs/dynamodb-schema.md) and [secret hygiene](SECURITY.md)

Production startup lazily composes scanners, persistent storage, reporting, alerts and remediation.
Set `CLOUD_PROVIDERS=aws`, `azure`, or `aws,azure`, and choose `STORAGE_BACKEND=dynamodb` or
`azure_blob`. Azure Blob uses `DefaultAzureCredential` with `AZURE_STORAGE_ACCOUNT_URL`.

## Safety

Scanning is read-only and never invokes remediation. A real mutation requires review, an explicit
one-time approval bound to the exact finding/action/parameters, operator authorization, and state
verification. Never deploy `infrastructure/demo` outside a disposable training environment. No
cloud credentials are hardcoded, committed, returned by the API, or intentionally logged.
