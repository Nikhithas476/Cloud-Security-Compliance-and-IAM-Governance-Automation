# Security Policy

## What must never be committed

Never commit real secrets or sensitive cloud information, including:

- `.env` files containing real values, API keys, passwords, tokens, or connection strings
- AWS access keys, shared credential files, role session tokens, or exported CLI profiles
- Azure client secrets, service-principal credentials, managed-identity tokens, or CLI state
- SSH private keys, signing keys, private certificates, keystores, or certificate bundles
- Terraform state, plan files containing secrets, sensitive `*.tfvars`, or `.terraform/` data
- production configuration, customer data, real account/subscription identifiers, or tenant data
- raw cloud scan results, security findings, generated reports, logs, or evidence exports

Use environment variables supplied by a secret manager, workload identity, managed identity, or
the standard AWS/Azure credential chain. Only placeholder values belong in `.env.example`.

Before every commit, run `git status`, inspect the full diff, and use an approved secret scanner.
If a secret is exposed, revoke and rotate it immediately; removing it from the latest file is not
enough because Git history may retain it.

## Reporting a vulnerability

Do not open a public issue containing sensitive details. Contact the repository owner privately
with a description, reproduction steps, affected versions, and any proposed mitigation.

