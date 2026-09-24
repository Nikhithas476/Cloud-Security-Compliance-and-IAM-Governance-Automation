variable "aws_region" {
  type    = string
  default = "us-east-1"
}
variable "name_prefix" {
  type    = string
  default = "cloud-security-governance"
}
variable "lambda_package_bucket" {
  type = string
}
variable "lambda_package_key" {
  type = string
}
variable "lambda_package_version" {
  type    = string
  default = null
}
variable "log_retention_days" {
  type    = number
  default = 90
}
variable "tags" {
  type    = map(string)
  default = {}
}


