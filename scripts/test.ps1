$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    python -m ruff format --check .
    python -m ruff check .
    python -m pytest --cov=cloud_security_governance --cov-report=term-missing --cov-fail-under=80
    python -m bandit -r src lambda azure_functions -x tests -ll
    python -m pip_audit -r requirements.txt

    $terraform = Get-Command terraform -ErrorAction SilentlyContinue
    if ($terraform) {
        terraform fmt -check -recursive infrastructure
        @(
            "infrastructure/terraform/aws",
            "infrastructure/terraform/azure",
            "infrastructure/demo/aws",
            "infrastructure/demo/azure"
        ) | ForEach-Object { terraform "-chdir=$_" validate }
    } else {
        Write-Warning "Terraform is unavailable; CI will enforce Terraform validation."
    }

    $cfnLint = Get-Command cfn-lint -ErrorAction SilentlyContinue
    if ($cfnLint) {
        cfn-lint infrastructure/cloudformation/aws.yaml
    } else {
        Write-Warning "cfn-lint is unavailable; CI will enforce CloudFormation validation."
    }
} finally {
    Pop-Location
}
