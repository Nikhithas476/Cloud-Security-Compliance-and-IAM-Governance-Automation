data "azurerm_subscription" "current" {
  subscription_id = var.subscription_id
}
resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}
locals {
  base = "${var.name_prefix}${random_string.suffix.result}"
  tags = merge(var.tags, {
    managed_by = "terraform", application = "cloud-security-governance"
  })
}

resource "azurerm_resource_group" "main" {
  name     = "rg-${local.base}"
  location = var.location
  tags     = local.tags
}
resource "azurerm_storage_account" "functions" {
  name                              = substr("st${local.base}", 0, 24)
  resource_group_name               = azurerm_resource_group.main.name
  location                          = azurerm_resource_group.main.location
  account_tier                      = "Standard"
  account_replication_type          = "LRS"
  min_tls_version                   = "TLS1_2"
  allow_nested_items_to_be_public   = false
  shared_access_key_enabled         = false
  infrastructure_encryption_enabled = true
  blob_properties {
    versioning_enabled = true
    delete_retention_policy {
      days = 7
    }
  }
  tags = local.tags
}
resource "azurerm_storage_container" "governance" {
  name                  = "governance-records"
  storage_account_name  = azurerm_storage_account.functions.name
  container_access_type = "private"
}
resource "azurerm_service_plan" "functions" {
  name                = "asp-${local.base}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  os_type             = "Linux"
  sku_name            = "Y1"
  tags                = local.tags
}
resource "azurerm_log_analytics_workspace" "main" {
  name                = "log-${local.base}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = "PerGB2018"
  retention_in_days   = 90
  tags                = local.tags
}
resource "azurerm_application_insights" "main" {
  name                = "appi-${local.base}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  workspace_id        = azurerm_log_analytics_workspace.main.id
  application_type    = "web"
  tags                = local.tags
}
resource "azurerm_linux_function_app" "main" {
  name                          = "func-${local.base}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = azurerm_resource_group.main.location
  service_plan_id               = azurerm_service_plan.functions.id
  storage_account_name          = azurerm_storage_account.functions.name
  storage_uses_managed_identity = true
  https_only                    = true
  public_network_access_enabled = false
  identity {
    type = "SystemAssigned"
  }
  site_config {
    minimum_tls_version = "1.2"
    application_stack {
      python_version = "3.11"
    }
  }
  app_settings = {
    APPLICATIONINSIGHTS_CONNECTION_STRING = azurerm_application_insights.main.connection_string
    WEBSITE_RUN_FROM_PACKAGE              = var.function_package_url
    AZURE_SUBSCRIPTION_ID                 = var.subscription_id
    AZURE_STORAGE_ACCOUNT_URL             = azurerm_storage_account.functions.primary_blob_endpoint
    AZURE_STORAGE_CONTAINER               = azurerm_storage_container.governance.name
    CLOUD_PROVIDERS                       = "azure"
    FUNCTION_ROLE                         = "scan"
    STORAGE_BACKEND                       = "azure_blob"
  }
  tags = local.tags
}

resource "azurerm_linux_function_app" "remediation" {
  name                          = "func-${local.base}-remediation"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = azurerm_resource_group.main.location
  service_plan_id               = azurerm_service_plan.functions.id
  storage_account_name          = azurerm_storage_account.functions.name
  storage_uses_managed_identity = true
  https_only                    = true
  public_network_access_enabled = false
  identity { type = "SystemAssigned" }
  site_config {
    minimum_tls_version = "1.2"
    application_stack { python_version = "3.11" }
  }
  app_settings = {
    APPLICATIONINSIGHTS_CONNECTION_STRING = azurerm_application_insights.main.connection_string
    WEBSITE_RUN_FROM_PACKAGE              = var.function_package_url
    AZURE_SUBSCRIPTION_ID                 = var.subscription_id
    AZURE_STORAGE_ACCOUNT_URL             = azurerm_storage_account.functions.primary_blob_endpoint
    AZURE_STORAGE_CONTAINER               = azurerm_storage_container.governance.name
    CLOUD_PROVIDERS                       = "azure"
    FUNCTION_ROLE                         = "remediation"
    STORAGE_BACKEND                       = "azure_blob"
  }
  tags = local.tags
}

resource "azurerm_role_assignment" "storage_blob" {
  scope                = azurerm_storage_account.functions.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_linux_function_app.main.identity[0].principal_id
}
resource "azurerm_role_assignment" "security_reader" {
  scope                = data.azurerm_subscription.current.id
  role_definition_name = "Security Reader"
  principal_id         = azurerm_linux_function_app.main.identity[0].principal_id
}
resource "azurerm_role_assignment" "reader" {
  scope                = data.azurerm_subscription.current.id
  role_definition_name = "Reader"
  principal_id         = azurerm_linux_function_app.main.identity[0].principal_id
}
resource "azurerm_role_assignment" "remediation_storage_blob" {
  scope                = azurerm_storage_account.functions.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_linux_function_app.remediation.identity[0].principal_id
}
resource "azurerm_role_definition" "controlled_rbac_remediator" {
  name        = "${var.name_prefix}-controlled-rbac-remediator"
  scope       = data.azurerm_subscription.current.id
  description = "Read and delete an explicitly approved Azure RBAC assignment."
  permissions {
    actions     = ["Microsoft.Authorization/roleAssignments/read", "Microsoft.Authorization/roleAssignments/delete"]
    not_actions = []
  }
  assignable_scopes = [data.azurerm_subscription.current.id]
}
resource "azurerm_role_assignment" "controlled_rbac_remediator" {
  scope              = data.azurerm_subscription.current.id
  role_definition_id = azurerm_role_definition.controlled_rbac_remediator.role_definition_resource_id
  principal_id       = azurerm_linux_function_app.remediation.identity[0].principal_id
}

resource "azurerm_subscription_policy_assignment" "storage_https" {
  name                 = "${var.name_prefix}-storage-https"
  display_name         = "Storage accounts must require secure transfer"
  subscription_id      = data.azurerm_subscription.current.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/404c3081-a854-4457-ae30-26a93ef643f9"
  identity {
    type = "SystemAssigned"
  }
  location = var.location
  parameters = jsonencode({
    effect = {
      value = "Audit"
    }
  })
}


