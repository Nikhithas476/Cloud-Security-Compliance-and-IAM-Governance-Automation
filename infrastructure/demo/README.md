# Intentionally vulnerable demonstration

These opt-in Terraform modules are disabled by default. They must never be used in production or an
account/subscription containing real data. Use disposable, isolated training environments with a
budget, SCP/Azure Policy guardrails, no network connectivity to production, and a short cleanup TTL.

The AWS module creates a user without MFA, an inline `Action: *`/`Resource: *` policy, and an
unencrypted 1 GiB EBS volume. AWS does not allow an access key creation timestamp to be backdated;
test stale-key behavior with the mocked scanner fixture, or wait 91 days in a dedicated long-lived
training account. Creating an IAM access key in Terraform is deliberately prohibited because its
secret would be stored in Terraform state.

The Azure module creates a deliberately weak storage configuration and an Owner assignment at the
demo resource-group scope. Modern Azure Storage always encrypts data at rest; the scanner's stricter
infrastructure-encryption/CMK requirements provide the encryption violation. The weak HTTPS/TLS
settings provide a Policy violation. Supply only a disposable demo principal object ID.

## Repeatable exercise

1. Set `enable_intentionally_vulnerable_resources=true`, run `terraform plan`, confirm the isolated
   target, then apply the appropriate demo module.
2. Configure read-only scanner identity and run `POST /scans` with an operator token.
3. Retrieve `/findings` and `/reports/{scan_id}`; retain only sanitized demo outputs.
4. Call the remediation engine's `review_and_request`, have a different authorized reviewer inspect
   the exact before-state/parameters, and explicitly approve the request.
5. Submit `POST /remediation/{finding_id}` with that one-time approval ID. Start with `dry_run=true`.
6. Confirm the audit record, post-change verification, and expected provider state.
7. Run a second scan/report and compare finding counts and risk scores.
8. Destroy the demo module immediately and verify the plan is empty. Access-key age, MFA enrollment,
   EBS encryption replacement, storage hardening, and unsupported policy changes remain manual demo
   steps because the remediation engine intentionally supports only narrowly controlled actions.

CI and normal deployment workflows never apply these modules.
