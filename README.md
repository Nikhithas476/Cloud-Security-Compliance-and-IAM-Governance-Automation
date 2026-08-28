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

