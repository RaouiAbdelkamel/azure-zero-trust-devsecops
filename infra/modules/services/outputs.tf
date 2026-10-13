output "acr_id" { value = azurerm_container_registry.this.id }
output "acr_login_server" { value = azurerm_container_registry.this.login_server }
output "signing_vault_id" { value = azurerm_key_vault.this["sign"].id }
output "signing_vault_uri" { value = azurerm_key_vault.this["sign"].vault_uri }
output "app_vault_id" { value = azurerm_key_vault.this["app"].id }
output "app_vault_uri" { value = azurerm_key_vault.this["app"].vault_uri }
