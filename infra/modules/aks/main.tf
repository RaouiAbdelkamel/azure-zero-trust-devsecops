resource "azurerm_user_assigned_identity" "control_plane" {
  name                = "id-${var.prefix}-aks-control"
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags
}
resource "azurerm_user_assigned_identity" "kubelet" {
  name                = "id-${var.prefix}-aks-kubelet"
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags
}
# Actions réseau explicites ; aucun Network Contributor sur le VNet entier.
resource "azurerm_role_definition" "network" {
  for_each = {
    subnet = [
      "Microsoft.Network/virtualNetworks/subnets/read",
      "Microsoft.Network/virtualNetworks/subnets/join/action"
    ]
    routes = [
      "Microsoft.Network/routeTables/read",
      "Microsoft.Network/routeTables/write",
      "Microsoft.Network/routeTables/routes/read",
      "Microsoft.Network/routeTables/routes/write",
      "Microsoft.Network/routeTables/routes/delete"
    ]
    vnet = [
      "Microsoft.Network/virtualNetworks/read",
      "Microsoft.Network/virtualNetworks/join/action",
      "Microsoft.Network/virtualNetworks/joinLoadBalancer/action"
    ]
    nsg = [
      "Microsoft.Network/networkSecurityGroups/read",
      "Microsoft.Network/networkSecurityGroups/write"
    ]
  }
  name              = "${var.prefix}-aks-${each.key}"
  scope             = var.resource_group_id
  assignable_scopes = [var.resource_group_id]
  permissions {
    actions = each.value
  }
}
resource "azurerm_role_assignment" "network" {
  for_each = {
    system = { scope = var.system_subnet_id, role = "subnet" }
    user   = { scope = var.user_subnet_id, role = "subnet" }
    routes = { scope = var.route_table_id, role = "routes" }
    vnet   = { scope = var.vnet_id, role = "vnet" }
    nsg    = { scope = var.aks_nsg_id, role = "nsg" }
  }
  scope                            = each.value.scope
  role_definition_id               = azurerm_role_definition.network[each.value.role].role_definition_resource_id
  principal_id                     = azurerm_user_assigned_identity.control_plane.principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
}
resource "azurerm_role_assignment" "dns" {
  scope                            = var.private_dns_zone_id
  role_definition_name             = "Private DNS Zone Contributor"
  principal_id                     = azurerm_user_assigned_identity.control_plane.principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
}
resource "azurerm_role_assignment" "kubelet_operator" {
  scope                            = azurerm_user_assigned_identity.kubelet.id
  role_definition_name             = "Managed Identity Operator"
  principal_id                     = azurerm_user_assigned_identity.control_plane.principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
}
resource "azurerm_role_assignment" "pull" {
  scope                            = var.acr_id
  role_definition_name             = "AcrPull"
  principal_id                     = azurerm_user_assigned_identity.kubelet.principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
}

resource "azurerm_kubernetes_cluster" "this" {
  name                                = "aks-${var.prefix}"
  resource_group_name                 = var.resource_group_name
  location                            = var.location
  node_resource_group                 = "rg-${var.prefix}-aks-nodes"
  dns_prefix                          = var.prefix
  kubernetes_version                  = var.kubernetes_version
  sku_tier                            = "Standard"
  private_cluster_enabled             = true
  private_cluster_public_fqdn_enabled = false
  private_dns_zone_id                 = var.private_dns_zone_id
  local_account_disabled              = true
  role_based_access_control_enabled   = true
  run_command_enabled                 = false
  oidc_issuer_enabled                 = true
  workload_identity_enabled           = true
  azure_policy_enabled                = true
  # Patch et images OS automatiques, dans des fenêtres UTC distinctes.
  automatic_upgrade_channel = "patch"
  node_os_upgrade_channel   = "NodeImage"
  azure_active_directory_role_based_access_control {
    tenant_id          = var.tenant_id
    azure_rbac_enabled = true
    # Pas de admin_group_object_ids : autorisation uniquement via Azure RBAC explicite.
  }
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.control_plane.id]
  }
  kubelet_identity {
    client_id                 = azurerm_user_assigned_identity.kubelet.client_id
    object_id                 = azurerm_user_assigned_identity.kubelet.principal_id
    user_assigned_identity_id = azurerm_user_assigned_identity.kubelet.id
  }
  default_node_pool {
    name                         = "system"
    temporary_name_for_rotation  = "systmp"
    vm_size                      = var.system_vm_size
    vnet_subnet_id               = var.system_subnet_id
    zones                        = ["1", "2", "3"]
    node_count                   = 3
    auto_scaling_enabled         = true
    min_count                    = 3
    max_count                    = 6
    max_pods                     = 50
    os_sku                       = "AzureLinux3"
    os_disk_type                 = "Managed"
    os_disk_size_gb              = 128
    node_public_ip_enabled       = false
    only_critical_addons_enabled = true
    upgrade_settings {
      max_surge                     = "1"
      drain_timeout_in_minutes      = 30
      node_soak_duration_in_minutes = 5
    }
    tags = var.tags
  }
  network_profile {
    network_plugin      = "azure"
    network_plugin_mode = "overlay"
    network_data_plane  = "cilium"
    # Phase 3 / Trivy AZU-0043 : moteur Cilium explicitement déclaré (AzureRM 4.81).
    # Les règles NetworkPolicy default-deny restent à déployer en Phase 4.
    network_policy    = "cilium"
    pod_cidr          = "10.244.0.0/16"
    service_cidr      = "10.96.0.0/16"
    dns_service_ip    = "10.96.0.10"
    outbound_type     = "userDefinedRouting"
    load_balancer_sku = "standard"
  }
  maintenance_window_auto_upgrade {
    frequency   = "Weekly"
    interval    = 1
    duration    = 4
    day_of_week = "Sunday"
    start_time  = "01:00"
    utc_offset  = "+00:00"
  }
  maintenance_window_node_os {
    frequency   = "Weekly"
    interval    = 1
    duration    = 4
    day_of_week = "Saturday"
    start_time  = "01:00"
    utc_offset  = "+00:00"
  }
  tags = var.tags
  lifecycle {
    # Le canal patch possède la version après création ; empêcher un downgrade Terraform.
    # Pour une montée mineure via Terraform, retirer cette exclusion dans une PR dédiée.
    ignore_changes = [default_node_pool[0].node_count, kubernetes_version]
  }
  depends_on = [
    azurerm_role_assignment.network, azurerm_role_assignment.dns,
    azurerm_role_assignment.kubelet_operator, azurerm_role_assignment.pull
  ]
}
resource "azurerm_kubernetes_cluster_node_pool" "app" {
  name                   = "apps"
  kubernetes_cluster_id  = azurerm_kubernetes_cluster.this.id
  vm_size                = var.user_vm_size
  vnet_subnet_id         = var.user_subnet_id
  zones                  = ["1", "2", "3"]
  mode                   = "User"
  os_sku                 = "AzureLinux3"
  os_disk_type           = "Managed"
  os_disk_size_gb        = 128
  node_public_ip_enabled = false
  node_count             = 3
  auto_scaling_enabled   = true
  min_count              = 3
  max_count              = 12
  max_pods               = 50
  node_labels            = { workload = "application" }
  node_taints            = ["workload=application:NoSchedule"]
  upgrade_settings {
    max_surge                     = "1"
    drain_timeout_in_minutes      = 30
    node_soak_duration_in_minutes = 5
  }
  tags = var.tags
  lifecycle { ignore_changes = [node_count] }
}
resource "azurerm_role_assignment" "admin" {
  scope                = azurerm_kubernetes_cluster.this.id
  role_definition_name = "Azure Kubernetes Service RBAC Cluster Admin"
  principal_id         = var.security_admin_group_object_id
  principal_type       = "Group"
}
resource "azurerm_role_assignment" "credentials" {
  scope                = azurerm_kubernetes_cluster.this.id
  role_definition_name = "Azure Kubernetes Service Cluster User Role"
  principal_id         = var.security_admin_group_object_id
  principal_type       = "Group"
}
