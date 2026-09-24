data "aws_caller_identity" "current" {}

locals {
  tags = merge(var.tags, {
    ManagedBy = "Terraform", Application = var.name_prefix
  })
}

resource "aws_dynamodb_table" "governance" {
  name         = "${var.name_prefix}-records"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "PK"
  range_key    = "SK"
  attribute {
    name = "PK"
    type = "S"
  }
  attribute {
    name = "SK"
    type = "S"
  }
  attribute {
    name = "GSI1PK"
    type = "S"
  }
  attribute {
    name = "GSI1SK"
    type = "S"
  }
  global_secondary_index {
    name            = "GSI1"
    hash_key        = "GSI1PK"
    range_key       = "GSI1SK"
    projection_type = "ALL"
  }
  point_in_time_recovery {
    enabled = true
  }
  server_side_encryption {
    enabled = true
  }
  tags = local.tags
}

resource "aws_iam_role" "lambda" {
  name = "${var.name_prefix}-lambda"
  assume_role_policy = jsonencode({
    Version = "2012-10-17", Statement = [{
      Effect = "Allow", Principal = {
        Service = "lambda.amazonaws.com"
      }, Action = "sts:AssumeRole"
    }]
  })
  tags = local.tags
}

resource "aws_iam_role" "remediation_lambda" {
  name = "${var.name_prefix}-remediation-lambda"
  assume_role_policy = jsonencode({
    Version = "2012-10-17", Statement = [{
      Effect = "Allow", Principal = {
        Service = "lambda.amazonaws.com"
      }, Action = "sts:AssumeRole"
    }]
  })
  tags = local.tags
}

resource "aws_iam_role_policy" "lambda" {
  role = aws_iam_role.lambda.id
  policy = jsonencode({
    Version = "2012-10-17", Statement = [
      {
        Sid = "Logs", Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.name_prefix}-*:log-stream:*"
      },
      {
        Sid = "Records", Effect = "Allow", Action = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query"], Resource = [aws_dynamodb_table.governance.arn, "${aws_dynamodb_table.governance.arn}/index/GSI1"]
      },
      {
        Sid = "ReadSecurityPosture", Effect = "Allow", Action = ["sts:GetCallerIdentity", "iam:Get*", "iam:List*", "s3:GetEncryptionConfiguration", "s3:ListAllMyBuckets", "ec2:DescribeVolumes", "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus", "config:DescribeConfigurationRecorders", "config:DescribeConfigurationRecorderStatus", "config:GetComplianceDetailsByConfigRule", "config:DescribeConfigRules"], Resource = "*"
      }
    ]
  })
}

resource "aws_lambda_function" "scan" {
  function_name                  = "${var.name_prefix}-scan"
  role                           = aws_iam_role.lambda.arn
  handler                        = "lambda.scan_handler.lambda_handler"
  runtime                        = "python3.11"
  s3_bucket                      = var.lambda_package_bucket
  s3_key                         = var.lambda_package_key
  s3_object_version              = var.lambda_package_version
  timeout                        = 300
  memory_size                    = 512
  reserved_concurrent_executions = 2
  environment {
    variables = {
      DYNAMODB_TABLE_NAME = aws_dynamodb_table.governance.name, LOG_LEVEL = "INFO"
    }
  }
  tracing_config {
    mode = "Active"
  }
  tags = local.tags
}

resource "aws_lambda_function" "remediation" {
  function_name                  = "${var.name_prefix}-remediation"
  role                           = aws_iam_role.remediation_lambda.arn
  handler                        = "lambda.remediation_handler.lambda_handler"
  runtime                        = "python3.11"
  s3_bucket                      = var.lambda_package_bucket
  s3_key                         = var.lambda_package_key
  s3_object_version              = var.lambda_package_version
  timeout                        = 60
  reserved_concurrent_executions = 1
  environment {
    variables = {
      DYNAMODB_TABLE_NAME = aws_dynamodb_table.governance.name, LOG_LEVEL = "INFO"
    }
  }
  tracing_config {
    mode = "Active"
  }
  tags = local.tags
}

resource "aws_iam_role_policy" "approved_remediation" {
  role = aws_iam_role.remediation_lambda.id
  policy = jsonencode({
    Version = "2012-10-17", Statement = [
      {
        Sid = "Logs", Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.name_prefix}-remediation:log-stream:*"
      },
      {
        Sid = "Records", Effect = "Allow", Action = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query"], Resource = [aws_dynamodb_table.governance.arn, "${aws_dynamodb_table.governance.arn}/index/GSI1"]
      },
      {
        Sid = "ControlledIAM", Effect = "Allow", Action = ["iam:UpdateAccessKey", "iam:CreatePolicyVersion", "iam:GetPolicy", "iam:GetPolicyVersion", "iam:ListAccessKeys"], Resource = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/*", "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/*"]
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "scan" {
  name              = "/aws/lambda/${aws_lambda_function.scan.function_name}"
  retention_in_days = var.log_retention_days
  tags              = local.tags
}
resource "aws_cloudwatch_log_group" "remediation" {
  name              = "/aws/lambda/${aws_lambda_function.remediation.function_name}"
  retention_in_days = var.log_retention_days
  tags              = local.tags
}

resource "aws_s3_bucket" "audit" {
  bucket_prefix = "${var.name_prefix}-audit-"
  force_destroy = false
  tags          = local.tags
}
resource "aws_s3_bucket_public_access_block" "audit" {
  bucket                  = aws_s3_bucket.audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id
  versioning_configuration {
    status = "Enabled"
  }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
resource "aws_s3_bucket_policy" "audit" {
  bucket = aws_s3_bucket.audit.id
  policy = jsonencode({
    Version = "2012-10-17", Statement = [
      {
        Effect = "Allow", Principal = {
          Service = "cloudtrail.amazonaws.com"
          }, Action = "s3:GetBucketAcl", Resource = aws_s3_bucket.audit.arn, Condition = {
          StringEquals = {
            "AWS:SourceArn" = "arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${var.name_prefix}"
          }
        }
      },
      {
        Effect = "Allow", Principal = {
          Service = "cloudtrail.amazonaws.com"
          }, Action = "s3:PutObject", Resource = "${aws_s3_bucket.audit.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*", Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control", "AWS:SourceArn" = "arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${var.name_prefix}"
          }
        }
      },
      {
        Effect = "Allow", Principal = {
          Service = "config.amazonaws.com"
          }, Action = "s3:GetBucketAcl", Resource = aws_s3_bucket.audit.arn, Condition = {
          StringEquals = {
            "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Effect = "Allow", Principal = {
          Service = "config.amazonaws.com"
          }, Action = "s3:PutObject", Resource = "${aws_s3_bucket.audit.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*", Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control", "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Effect = "Deny", Principal = "*", Action = "s3:*", Resource = [aws_s3_bucket.audit.arn, "${aws_s3_bucket.audit.arn}/*"], Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}
resource "aws_cloudtrail" "governance" {
  name                          = var.name_prefix
  s3_bucket_name                = aws_s3_bucket.audit.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  depends_on                    = [aws_s3_bucket_policy.audit]
  tags                          = local.tags
}

resource "aws_iam_role" "config" {
  name = "${var.name_prefix}-config"
  assume_role_policy = jsonencode({
    Version = "2012-10-17", Statement = [{
      Effect = "Allow", Principal = {
        Service = "config.amazonaws.com"
      }, Action = "sts:AssumeRole"
    }]
  })
  tags = local.tags
}
resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}
resource "aws_config_delivery_channel" "governance" {
  name           = var.name_prefix
  s3_bucket_name = aws_s3_bucket.audit.id
}
resource "aws_config_configuration_recorder" "governance" {
  name     = var.name_prefix
  role_arn = aws_iam_role.config.arn
  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}
resource "aws_config_configuration_recorder_status" "governance" {
  name       = aws_config_configuration_recorder.governance.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.governance]
}


