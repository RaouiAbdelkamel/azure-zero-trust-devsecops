resource "azurerm_container_registry" "this" {
  name                          = "acr${var.prefix}${var.unique_suffix}"
  resource_group_name           = var.resource_group_name
  location                      = var.location
  sku                           = "Premium"
  admin_enabled                 = false
  public_network_access_enabled = false
  anonymous_pull_enabled        = false
  network_rule_bypass_option    = "None"
  zone_redundancy_enabled       = true
  data_endpoint_enabled         = true
  export_policy_enabled         = false
  role_assignment_mode          = "LegacyRegistryPermissions"
  # Mode RBAC classique : AcrPull pour le kubelet ; registre dédié à cette application.
  # Ne pas activer ABAC sans remplacer les rôles et revalider le pull AKS.
  tags = var.tags
  lifecycle { prevent_destroy = true }
}
resource "azurerm_private_endpoint" "acr" {
  name                = "pe-acr-${var.prefix}"
  resource_group_name = var.resource_group_name
  location            = var.location
  subnet_id           = var.endpoint_subnet_id
  private_service_connection {
    name                           = "acr"
    private_connection_resource_id = azurerm_container_registry.this.id
    is_manual_connection           = false
    subresource_names              = ["registry"]
  }
  private_dns_zone_group {
    name                 = "acr"
    private_dns_zone_ids = [var.acr_dns_zone_id]
  }
  tags = var.tags
}
# Deux coffres : la CI de signature ne peut pas lire les secrets de l'application.
resource "azurerm_key_vault" "this" {
  for_each                        = toset(["sign", "app"])
  name                            = "kv-${var.prefix}-${each.key}-${var.unique_suffix}"
  resource_group_name             = var.resource_group_name
  location                        = var.location
  tenant_id                       = var.tenant_id
  sku_name                        = "premium"
  rbac_authorization_enabled      = true
  purge_protection_enabled        = true
  soft_delete_retention_days      = 90
  public_network_access_enabled   = false
  enabled_for_deployment          = false
  enabled_for_disk_encryption     = false
  enabled_for_template_deployment = false
  network_acls {
    bypass         = "None"
    default_action = "Deny"
  }
  # Aucune access_policy, clé, secret ou clé privée injectée dans Terraform/state.
  tags = var.tags
  lifecycle { prevent_destroy = true }
}
resource "azurerm_private_endpoint" "vault" {
  for_each            = azurerm_key_vault.this
  name                = "pe-kv-${var.prefix}-${each.key}"
  resource_group_name = var.resource_group_name
  location            = var.location
  subnet_id           = var.endpoint_subnet_id
  private_service_connection {
    name                           = "vault"
    private_connection_resource_id = each.value.id
    is_manual_connection           = false
    subresource_names              = ["vault"]
  }
  private_dns_zone_group {
    name                 = "vault"
    private_dns_zone_ids = [var.vault_dns_zone_id]
  }
  tags = var.tags
}
