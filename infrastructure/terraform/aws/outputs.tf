output "dynamodb_table_name" {
  value = aws_dynamodb_table.governance.name
}
output "scan_lambda_arn" {
  value = aws_lambda_function.scan.arn
}
output "remediation_lambda_arn" {
  value = aws_lambda_function.remediation.arn
}
output "cloudtrail_arn" {
  value = aws_cloudtrail.governance.arn
}


