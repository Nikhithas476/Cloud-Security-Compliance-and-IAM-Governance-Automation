# Setup and configuration

Use Python 3.11+ and install `.[dev]`. Defaults load from `config/default.yaml`, then supported
environment variables override them. `.env.example` is reference-only; `.env` is ignored and is not
auto-loaded.

Configure distinct random `API_READER_TOKEN`, `API_OPERATOR_TOKEN`, and `API_REVIEWER_TOKEN`
values of at least 32 characters. Set `CLOUD_PROVIDERS` to `aws`, `azure`, or `aws,azure`.
Select `STORAGE_BACKEND=dynamodb` with `DYNAMODB_TABLE_NAME`, or
`STORAGE_BACKEND=azure_blob` with the HTTPS `AZURE_STORAGE_ACCOUNT_URL` and private
`AZURE_STORAGE_CONTAINER`. The API and serverless adapters construct these services on first use.

For AWS, use boto3's standard chain (workload/instance role, `AWS_PROFILE`, environment or optional
`AWS_ROLE_ARN`) and set `AWS_REGION`. For Azure, set `AZURE_SUBSCRIPTION_ID` and use
`DefaultAzureCredential` through workload identity, managed identity, CLI or approved environment
configuration. Never put keys or client secrets in source, YAML, Terraform variables, tests or logs.

```powershell
ruff format --check .
ruff check .
pytest --cov=cloud_security_governance --cov-fail-under=80
uvicorn cloud_security_governance.main:app --app-dir src
```

Production identities and deployment steps are documented in [infrastructure](../infrastructure/README.md).
