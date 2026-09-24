variable "subscription_id" {
  type      = string
  sensitive = true
}
variable "location" {
  type    = string
  default = "eastus"
}
variable "name_prefix" {
  type    = string
  default = "csgov"
  validation {
    condition     = can(regex("^[a-z0-9]{3,12}$", var.name_prefix))
    error_message = "name_prefix must be 3-12 lowercase alphanumeric characters."
  }
}
variable "function_package_url" {
  type      = string
  sensitive = true
  default   = ""
}
variable "tags" {
  type    = map(string)
  default = {}
}


