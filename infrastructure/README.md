# Infrastructure deployment

The production modules are under `terraform/aws` and `terraform/azure`. The AWS CloudFormation
alternative is `cloudformation/aws.yaml`. They create separate scan and remediation identities;
only the remediation identity can perform the two controlled IAM mutations.

AWS functions receive `CLOUD_PROVIDERS=aws` and use DynamoDB. Azure functions receive
`CLOUD_PROVIDERS=azure` and use a private Blob container through managed identity. Separate
`FUNCTION_ROLE` values prevent the scan deployment from serving remediation and vice versa. Both
packages use the Python v2 `FunctionApp` registration discovered through the repository-root
`function_app.py` and `host.json` files.

## Prerequisites

- Terraform 1.6 or newer and provider authentication through AWS/Azure workload identity
- A versioned S3 object containing the Lambda deployment package
- An Azure Function package URL stored in a secret manager (never commit its SAS token)
- Permission to create the documented resources and role assignments

## Terraform

Run `terraform fmt -check -recursive infrastructure/terraform`, then in either provider directory
run `terraform init`, `terraform validate`, `terraform plan -out=tfplan`, review the plan, and only
then `terraform apply tfplan`. Supply values through protected CI variables or an ignored `.tfvars`
file. Use a remote encrypted backend with locking in team environments. Never commit state or plan
files. Important outputs expose resource names and ARNs, never credentials.

AWS requires `lambda_package_bucket` and `lambda_package_key`. Azure requires `subscription_id`;
`function_package_url` is sensitive and should come from a secret store. Private Azure Function
network access requires a private endpoint/VNet integration in the target network before clients
can reach it.

## CloudFormation

Validate locally with `cfn-lint infrastructure/cloudformation/aws.yaml`. Upload an immutable Lambda
package to S3, then deploy with a change set, providing `CodeBucket`, `CodeKey`, and optionally
`CodeVersion`. Review the IAM capability and change set before execution. Example:

```text
aws cloudformation deploy --template-file infrastructure/cloudformation/aws.yaml \
  --stack-name cloud-security-governance --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides CodeBucket=YOUR_BUCKET CodeKey=packages/app.zip
```

Do not place credentials, tokens, package SAS URLs, account data, or real scan results in parameters,
outputs, Terraform state committed to Git, or command logs.
