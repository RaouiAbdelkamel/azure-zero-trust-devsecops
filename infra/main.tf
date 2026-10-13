resource "azurerm_resource_group" "platform" {
  name     = "rg-${var.prefix}"
  location = var.location
  tags     = var.tags
}

module "network" {
  source              = "./modules/network"
  prefix              = var.prefix
  resource_group_name = azurerm_resource_group.platform.name
  location            = var.location
  tags                = var.tags
}

module "services" {
  source              = "./modules/services"
  prefix              = var.prefix
  unique_suffix       = var.unique_suffix
  resource_group_name = azurerm_resource_group.platform.name
  location            = var.location
  tenant_id           = var.tenant_id
  endpoint_subnet_id  = module.network.endpoint_subnet_id
  acr_dns_zone_id     = module.network.acr_dns_zone_id
  vault_dns_zone_id   = module.network.vault_dns_zone_id
  tags                = var.tags
}

module "aks" {
  source                         = "./modules/aks"
  prefix                         = var.prefix
  resource_group_name            = azurerm_resource_group.platform.name
  resource_group_id              = azurerm_resource_group.platform.id
  location                       = var.location
  tenant_id                      = var.tenant_id
  kubernetes_version             = var.kubernetes_version
  security_admin_group_object_id = var.security_admin_group_object_id
  system_subnet_id               = module.network.system_subnet_id
  user_subnet_id                 = module.network.user_subnet_id
  vnet_id                        = module.network.vnet_id
  route_table_id                 = module.network.route_table_id
  aks_nsg_id                     = module.network.aks_nsg_id
  private_dns_zone_id            = module.network.aks_dns_zone_id
  acr_id                         = module.services.acr_id
  system_vm_size                 = var.system_vm_size
  user_vm_size                   = var.user_vm_size
  tags                           = var.tags
  # Le pare-feu, ses règles et les routes doivent être opérationnels avant bootstrap.
  depends_on = [module.network, module.services]
}

module "identities" {
  source                   = "./modules/identities"
  prefix                   = var.prefix
  resource_group_name      = azurerm_resource_group.platform.name
  resource_group_id        = azurerm_resource_group.platform.id
  location                 = var.location
  github_repository        = var.github_repository
  github_build_environment = var.github_build_environment
  github_sign_environment  = var.github_sign_environment
  aks_oidc_issuer_url      = module.aks.oidc_issuer_url
  workload_namespace       = var.workload_namespace
  ratify_namespace         = var.ratify_namespace
  ratify_service_account   = var.ratify_service_account
  acr_id                   = module.services.acr_id
  signing_vault_id         = module.services.signing_vault_id
  tags                     = var.tags
}

resource "azurerm_log_analytics_workspace" "security" {
  name                       = "law-${var.prefix}"
  location                   = var.location
  resource_group_name        = azurerm_resource_group.platform.name
  sku                        = "PerGB2018"
  retention_in_days          = 90
  internet_ingestion_enabled = false
  internet_query_enabled     = false
  tags                       = var.tags
}

resource "azurerm_monitor_private_link_scope" "security" {
  name                  = "ampls-${var.prefix}"
  resource_group_name   = azurerm_resource_group.platform.name
  ingestion_access_mode = "PrivateOnly"
  query_access_mode     = "PrivateOnly"
  tags                  = var.tags
}
resource "azurerm_monitor_private_link_scoped_service" "security" {
  name                = "security-workspace"
  resource_group_name = azurerm_resource_group.platform.name
  scope_name          = azurerm_monitor_private_link_scope.security.name
  linked_resource_id  = azurerm_log_analytics_workspace.security.id
}
resource "azurerm_private_endpoint" "monitor" {
  name                = "pe-monitor-${var.prefix}"
  resource_group_name = azurerm_resource_group.platform.name
  location            = var.location
  subnet_id           = module.network.endpoint_subnet_id
  private_service_connection {
    name                           = "monitor"
    private_connection_resource_id = azurerm_monitor_private_link_scope.security.id
    subresource_names              = ["azuremonitor"]
    is_manual_connection           = false
  }
  private_dns_zone_group {
    name                 = "monitor"
    private_dns_zone_ids = module.network.monitor_dns_zone_ids
  }
  tags       = var.tags
  depends_on = [azurerm_monitor_private_link_scoped_service.security]
}

locals {
  # Journaux de ressources transmis par Azure ; pas d'agent de collecte dans AKS.
  diagnostic_targets = {
    aks      = module.aks.id
    acr      = module.services.acr_id
    signing  = module.services.signing_vault_id
    app      = module.services.app_vault_id
    firewall = module.network.firewall_id
  }
}
resource "azurerm_monitor_diagnostic_setting" "security" {
  for_each                       = local.diagnostic_targets
  name                           = "security-audit"
  target_resource_id             = each.value
  log_analytics_workspace_id     = azurerm_log_analytics_workspace.security.id
  log_analytics_destination_type = "Dedicated"
  enabled_log {
    category_group = "allLogs"
  }
  enabled_metric {
    category = "AllMetrics"
  }
}
