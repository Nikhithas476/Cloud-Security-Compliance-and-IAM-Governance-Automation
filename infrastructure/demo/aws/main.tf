terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source = "hashicorp/aws", version = "~> 5.0"
    }
  }
}
provider "aws" {
  region = var.aws_region
}
variable "aws_region" {
  type    = string
  default = "us-east-1"
}
variable "enable_intentionally_vulnerable_resources" {
  type    = bool
  default = false
}
variable "demo_owner_tag" {
  type    = string
  default = "security-training"
}

resource "aws_iam_user" "no_mfa" {
  count = var.enable_intentionally_vulnerable_resources ? 1 : 0
  name  = "csgov-demo-no-mfa"
  tags = {
    Purpose = var.demo_owner_tag
  }
}
resource "aws_iam_user_policy" "overly_permissive" {
  count = var.enable_intentionally_vulnerable_resources ? 1 : 0
  name  = "csgov-demo-overly-permissive"
  user  = aws_iam_user.no_mfa[0].name
  policy = jsonencode({
    Version = "2012-10-17", Statement = [{
      Sid = "IntentionalDemoOnly", Effect = "Allow", Action = "*", Resource = "*"
    }]
  })
}
resource "aws_ebs_volume" "unencrypted" {
  count             = var.enable_intentionally_vulnerable_resources ? 1 : 0
  availability_zone = "${var.aws_region}a"
  size              = 1
  encrypted         = false
  tags = {
    Name = "csgov-demo-unencrypted", Purpose = var.demo_owner_tag
  }
}

output "warning" {
  value = "INTENTIONALLY VULNERABLE: deploy only in an isolated disposable account"
}
output "demo_user_name" {
  value = try(aws_iam_user.no_mfa[0].name, null)
}


