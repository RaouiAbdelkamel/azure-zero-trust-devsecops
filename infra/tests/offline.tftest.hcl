# Plan complet simulé : vérifie le graphe de dépendances sans accès Azure.
# Ces tests ne remplacent ni un vrai plan régional ni les tests d'admission Phase 4.
mock_provider "azurerm" {}

variables {
  subscription_id                = "00000000-0000-0000-0000-000000000001"
  tenant_id                      = "00000000-0000-0000-0000-000000000002"
  security_admin_group_object_id = "00000000-0000-0000-0000-000000000003"
  unique_suffix                  = "a1b2c3d4"
  kubernetes_version             = "1.35.1" # Valeur syntaxique simulée ; aucune disponibilité régionale présumée.
  github_repository              = "example/security"
}

run "root_dependency_graph" {
  command = plan
  assert {
    condition     = toset(keys(output.identity_client_ids)) == toset(["build", "sign", "ratify", "app"])
    error_message = "Les quatre fonctions doivent garder des identités distinctes."
  }
  assert {
    condition     = !azurerm_log_analytics_workspace.security.internet_ingestion_enabled && !azurerm_log_analytics_workspace.security.internet_query_enabled
    error_message = "Les journaux doivent rester accessibles par Private Link."
  }
}

run "aks_security_contract" {
  command = plan
  module { source = "./modules/aks" }
  variables {
    prefix                         = "ztprod"
    resource_group_name            = "rg-ztprod"
    resource_group_id              = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-ztprod"
    location                       = "westeurope"
    tenant_id                      = "00000000-0000-0000-0000-000000000002"
    kubernetes_version             = "1.35.1"
    security_admin_group_object_id = "00000000-0000-0000-0000-000000000003"
    system_subnet_id               = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-ztprod/providers/Microsoft.Network/virtualNetworks/vnet/subnets/system"
    user_subnet_id                 = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-ztprod/providers/Microsoft.Network/virtualNetworks/vnet/subnets/user"
    vnet_id                        = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-ztprod/providers/Microsoft.Network/virtualNetworks/vnet"
    route_table_id                 = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-ztprod/providers/Microsoft.Network/routeTables/rt"
    aks_nsg_id                     = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-ztprod/providers/Microsoft.Network/networkSecurityGroups/nsg"
    private_dns_zone_id            = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-ztprod/providers/Microsoft.Network/privateDnsZones/privatelink.westeurope.azmk8s.io"
    acr_id                         = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-ztprod/providers/Microsoft.ContainerRegistry/registries/acrztprod"
    system_vm_size                 = "Standard_D4s_v5"
    user_vm_size                   = "Standard_D4s_v5"
    tags                           = {}
  }
  assert {
    condition = (
      azurerm_kubernetes_cluster.this.private_cluster_enabled &&
      !azurerm_kubernetes_cluster.this.private_cluster_public_fqdn_enabled &&
      azurerm_kubernetes_cluster.this.local_account_disabled &&
      !azurerm_kubernetes_cluster.this.run_command_enabled &&
      azurerm_kubernetes_cluster.this.oidc_issuer_enabled &&
      azurerm_kubernetes_cluster.this.workload_identity_enabled &&
      azurerm_kubernetes_cluster.this.azure_policy_enabled &&
      azurerm_kubernetes_cluster.this.azure_active_directory_role_based_access_control[0].azure_rbac_enabled
    )
    error_message = "Un accès public/local ou la désactivation des contrôles Zero Trust doit bloquer la livraison."
  }
  assert {
    condition = (
      azurerm_kubernetes_cluster.this.network_profile[0].network_data_plane == "cilium" &&
      azurerm_kubernetes_cluster.this.network_profile[0].outbound_type == "userDefinedRouting" &&
      !azurerm_kubernetes_cluster.this.default_node_pool[0].node_public_ip_enabled &&
      !azurerm_kubernetes_cluster_node_pool.app.node_public_ip_enabled
    )
    error_message = "Cilium et la sortie contrôlée sans IP publique de nœud sont obligatoires."
  }
}

run "private_services_contract" {
  command = plan
  module { source = "./modules/services" }
  variables {
    prefix              = "ztprod"
    unique_suffix       = "a1b2c3d4"
    resource_group_name = "rg-ztprod"
    location            = "westeurope"
    tenant_id           = "00000000-0000-0000-0000-000000000002"
    endpoint_subnet_id  = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-ztprod/providers/Microsoft.Network/virtualNetworks/vnet/subnets/endpoints"
    acr_dns_zone_id     = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-ztprod/providers/Microsoft.Network/privateDnsZones/privatelink.azurecr.io"
    vault_dns_zone_id   = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-ztprod/providers/Microsoft.Network/privateDnsZones/privatelink.vaultcore.azure.net"
    tags                = {}
  }
  assert {
    condition = (
      !azurerm_container_registry.this.public_network_access_enabled &&
      !azurerm_container_registry.this.admin_enabled &&
      !azurerm_container_registry.this.anonymous_pull_enabled &&
      !azurerm_container_registry.this.export_policy_enabled &&
      azurerm_container_registry.this.role_assignment_mode == "LegacyRegistryPermissions"
    )
    error_message = "ACR doit rester privé, sans admin et compatible avec les rôles kubelet."
  }
  assert {
    condition = alltrue([for vault in azurerm_key_vault.this :
      vault.rbac_authorization_enabled && vault.purge_protection_enabled &&
      vault.soft_delete_retention_days == 90 && !vault.public_network_access_enabled
    ])
    error_message = "Chaque coffre doit garder RBAC, protection purge et accès privé."
  }
}
