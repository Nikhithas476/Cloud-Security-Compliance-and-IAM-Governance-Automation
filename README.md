# Cloud Security Compliance and IAM Governance Automation

Foundation for a Python service that will automate cloud security compliance and IAM governance
across AWS and Azure. Day 1 establishes the application, configuration, logging, tests, and
deployment layout. Cloud scanning is intentionally not implemented yet.

## Requirements

- Python 3.11 or newer
- A virtual environment

## Local setup

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
Copy-Item .env.example .env
```

The application reads ordinary environment variables and an optional YAML configuration file.
The `.env` file is a developer reference and is not automatically loaded, preventing accidental
secret ingestion. Set variables in your shell or deployment platform as needed.

## Run

```powershell
uvicorn cloud_security_governance.main:app --app-dir src --reload
```

Open `http://127.0.0.1:8000/health` to verify the service.

## Test and lint

```powershell
pytest
ruff check .
```

## Project layout

- `src/` — application package, configuration, logging, and API
- `src/cloud_security_governance/models/` — validated, JSON-serializable domain models
- `tests/` — unit and API tests
- `config/` — safe default YAML configuration
- `docs/` — architecture and development documentation
- `scripts/` — local automation helpers
- `infrastructure/` — future infrastructure-as-code modules
- `lambda/` — AWS Lambda entry point
- `azure_functions/` — Azure Functions entry point
- `.github/workflows/` — continuous integration

## Security

Never commit credentials or scan output. Read [SECURITY.md](SECURITY.md) before contributing.

## Domain models

Core provider-neutral models are exported from `cloud_security_governance.models`. They use strict
Pydantic validation and support `model_dump_json()` and `model_validate_json()` for JSON round
trips. The foundation includes no AWS or Azure API calls.

## AWS authentication foundation

`AWSScanner` uses boto3's standard credential resolution chain. It supports `AWS_PROFILE`,
`AWS_REGION`, and optional `AWS_ROLE_ARN` role assumption. Credentials must come from the AWS CLI,
environment, workload identity, instance/container role, or another standard boto3 provider; never
put credential values in this repository. Only the read-only STS identity operation is available.
Resource scanning is intentionally not implemented yet.

### IAM security scanning

`AWSIAMScanner` performs read-only IAM checks for unrestricted policy actions/resources, users
without MFA, access keys unused for more than 90 days, and root-account access keys. It evaluates
customer-managed policies and inline user, role, and group policies. Findings use the common model
and explicitly indicate whether remediation is available. The scanner never changes IAM resources.
