terraform {
  required_version = ">= 1.6.0"
  required_providers {
    azurerm = {
      source = "hashicorp/azurerm", version = "~> 3.100"
    }
    random = {
      source = "hashicorp/random", version = "~> 3.6"
    }
  }
}
provider "azurerm" {
  features {}
}
variable "enable_intentionally_vulnerable_resources" {
  type    = bool
  default = false
}
variable "location" {
  type    = string
  default = "eastus"
}
variable "privileged_principal_object_id" {
  type    = string
  default = "00000000-0000-0000-0000-000000000000"
}
resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}
resource "azurerm_resource_group" "demo" {
  count    = var.enable_intentionally_vulnerable_resources ? 1 : 0
  name     = "rg-csgov-vulnerable-${random_string.suffix.result}"
  location = var.location
  tags = {
    Purpose = "intentional-security-demo"
  }
}
resource "azurerm_storage_account" "violation" {
  count                             = var.enable_intentionally_vulnerable_resources ? 1 : 0
  name                              = "stcsgovbad${random_string.suffix.result}"
  resource_group_name               = azurerm_resource_group.demo[0].name
  location                          = azurerm_resource_group.demo[0].location
  account_tier                      = "Standard"
  account_replication_type          = "LRS"
  https_traffic_only_enabled        = false
  min_tls_version                   = "TLS1_0"
  infrastructure_encryption_enabled = false
  allow_nested_items_to_be_public   = true
  tags = {
    Purpose = "intentional-security-demo"
  }
}
resource "azurerm_role_assignment" "excessive" {
  count                = var.enable_intentionally_vulnerable_resources ? 1 : 0
  scope                = azurerm_resource_group.demo[0].id
  role_definition_name = "Owner"
  principal_id         = var.privileged_principal_object_id
}
output "warning" {
  value = "INTENTIONALLY VULNERABLE: deploy only in an isolated disposable subscription"
}


