output "resource_group_name" {
  value = azurerm_resource_group.main.name
}
output "function_app_name" {
  value = azurerm_linux_function_app.main.name
}
output "remediation_function_app_name" {
  value = azurerm_linux_function_app.remediation.name
}
output "function_principal_id" {
  value = azurerm_linux_function_app.main.identity[0].principal_id
}
output "storage_account_name" {
  value = azurerm_storage_account.functions.name
}


