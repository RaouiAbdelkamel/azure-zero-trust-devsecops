locals {
  # Plan IP réservé : vérifier les chevauchements avec le hub/VPN avant déploiement.
  subnets = {
    system    = { name = "snet-aks-system", cidr = "10.40.0.0/23" }
    user      = { name = "snet-aks-user", cidr = "10.40.4.0/22" }
    endpoints = { name = "snet-private-endpoints", cidr = "10.40.8.0/24" }
    runners   = { name = "snet-ci-runners", cidr = "10.40.9.0/24" }
    firewall  = { name = "AzureFirewallSubnet", cidr = "10.40.10.0/26" }
  }
  aks_cidrs = [local.subnets.system.cidr, local.subnets.user.cidr]
  # CNI Overlay : NSG doit laisser passer node/node, node/pod et pod/pod.
  cluster_cidrs = concat(local.aks_cidrs, ["10.244.0.0/16"])
  dns_zones = {
    acr     = "privatelink.azurecr.io"
    vault   = "privatelink.vaultcore.azure.net"
    aks     = "privatelink.${var.location}.azmk8s.io"
    monitor = "privatelink.monitor.azure.com"
    oms     = "privatelink.oms.opinsights.azure.com"
    ods     = "privatelink.ods.opinsights.azure.com"
    agent   = "privatelink.agentsvc.azure-automation.net"
    blob    = "privatelink.blob.core.windows.net"
  }
}
resource "azurerm_virtual_network" "this" {
  name                = "vnet-${var.prefix}"
  resource_group_name = var.resource_group_name
  location            = var.location
  address_space       = ["10.40.0.0/16"]
  tags                = var.tags
}
resource "azurerm_subnet" "this" {
  for_each                        = local.subnets
  name                            = each.value.name
  resource_group_name             = var.resource_group_name
  virtual_network_name            = azurerm_virtual_network.this.name
  address_prefixes                = [each.value.cidr]
  default_outbound_access_enabled = false
  # NSG/UDR sur NIC des Private Endpoints : désactivés ; filtrage côté sources.
  private_endpoint_network_policies = "Disabled"
}
resource "azurerm_private_dns_zone" "this" {
  for_each            = local.dns_zones
  name                = each.value
  resource_group_name = var.resource_group_name
  tags                = var.tags
}
resource "azurerm_private_dns_zone_virtual_network_link" "this" {
  for_each              = local.dns_zones
  name                  = "link-${var.prefix}"
  resource_group_name   = var.resource_group_name
  private_dns_zone_name = azurerm_private_dns_zone.this[each.key].name
  virtual_network_id    = azurerm_virtual_network.this.id
  registration_enabled  = false
  tags                  = var.tags
}
resource "azurerm_public_ip" "firewall" {
  name                = "pip-fw-${var.prefix}"
  resource_group_name = var.resource_group_name
  location            = var.location
  allocation_method   = "Static"
  sku                 = "Standard"
  zones               = ["1", "2", "3"]
  tags                = var.tags
}
resource "azurerm_firewall_policy" "this" {
  name                     = "fwpol-${var.prefix}"
  resource_group_name      = var.resource_group_name
  location                 = var.location
  sku                      = "Premium"
  threat_intelligence_mode = "Deny"
  dns { proxy_enabled = true }
  intrusion_detection { mode = "Deny" }
  tags = var.tags
}
resource "azurerm_firewall" "this" {
  name                = "fw-${var.prefix}"
  resource_group_name = var.resource_group_name
  location            = var.location
  sku_name            = "AZFW_VNet"
  sku_tier            = "Premium"
  zones               = ["1", "2", "3"]
  firewall_policy_id  = azurerm_firewall_policy.this.id
  ip_configuration {
    name                 = "egress-only"
    subnet_id            = azurerm_subnet.this["firewall"].id
    public_ip_address_id = azurerm_public_ip.firewall.id
  }
  # Aucune DNAT : cette IP publique ne publie ni l'application ni AKS.
  tags = var.tags
}
resource "azurerm_firewall_policy_rule_collection_group" "aks" {
  name               = "aks-platform-dependencies"
  firewall_policy_id = azurerm_firewall_policy.this.id
  priority           = 200
  application_rule_collection {
    name     = "aks-required-fqdns"
    priority = 200
    action   = "Allow"
    rule {
      name                  = "aks-managed-list"
      source_addresses      = local.aks_cidrs
      destination_fqdn_tags = ["AzureKubernetesService"]
      protocols {
        type = "Https"
        port = 443
      }
      protocols {
        type = "Http"
        port = 80
      }
    }
    rule {
      name             = "entra-and-policy"
      source_addresses = local.aks_cidrs
      destination_fqdns = [
        "login.microsoftonline.com", "management.azure.com",
        "data.policy.core.windows.net", "store.policy.core.windows.net",
        "dc.services.visualstudio.com"
      ]
      protocols {
        type = "Https"
        port = 443
      }
    }
  }
  # Pas de règle réseau AzureCloud:443 qui court-circuiterait le filtrage FQDN.
  # Cluster privé : pas de tunnels publics 1194/9000. AzureLinux utilise le temps hôte.
}

resource "azurerm_route_table" "aks" {
  name                          = "rt-aks-${var.prefix}"
  location                      = var.location
  resource_group_name           = var.resource_group_name
  bgp_route_propagation_enabled = false
  route {
    name                   = "default-via-firewall"
    address_prefix         = "0.0.0.0/0"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = azurerm_firewall.this.ip_configuration[0].private_ip_address
  }
  tags = var.tags
}
resource "azurerm_subnet_route_table_association" "aks" {
  for_each       = toset(["system", "user"])
  subnet_id      = azurerm_subnet.this[each.value].id
  route_table_id = azurerm_route_table.aks.id
}
# Route table CI distincte : le control plane AKS ne peut pas modifier les routes CI.
resource "azurerm_route_table" "runners" {
  name                          = "rt-ci-${var.prefix}"
  location                      = var.location
  resource_group_name           = var.resource_group_name
  bgp_route_propagation_enabled = false
  route {
    name                   = "default-via-firewall"
    address_prefix         = "0.0.0.0/0"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = azurerm_firewall.this.ip_configuration[0].private_ip_address
  }
  tags = var.tags
}
resource "azurerm_subnet_route_table_association" "runners" {
  subnet_id      = azurerm_subnet.this["runners"].id
  route_table_id = azurerm_route_table.runners.id
}
# Le DNS proxy utilise Azure DNS dans ce VNet et résout les zones Private Link liées.
resource "azurerm_virtual_network_dns_servers" "this" {
  virtual_network_id = azurerm_virtual_network.this.id
  dns_servers        = [azurerm_firewall.this.ip_configuration[0].private_ip_address]
}

resource "azurerm_network_security_group" "aks" {
  name                = "nsg-aks-${var.prefix}"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags
  security_rule {
    name                         = "AllowNodeAndControlPlane"
    priority                     = 100
    direction                    = "Inbound"
    access                       = "Allow"
    protocol                     = "*"
    source_port_range            = "*"
    destination_port_range       = "*"
    source_address_prefixes      = local.cluster_cidrs
    destination_address_prefixes = local.cluster_cidrs
  }
  security_rule {
    name                       = "AllowPrivateRunnerToApi"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = local.subnets.runners.cidr
    destination_address_prefix = local.subnets.system.cidr
  }
  security_rule {
    name                         = "AllowLoadBalancerProbes"
    priority                     = 120
    direction                    = "Inbound"
    access                       = "Allow"
    protocol                     = "Tcp"
    source_port_range            = "*"
    destination_port_range       = "*"
    source_address_prefix        = "AzureLoadBalancer"
    destination_address_prefixes = local.aks_cidrs
  }
  security_rule {
    name                       = "DenyOtherInbound"
    priority                   = 4000
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  security_rule {
    name                         = "AllowNodeTraffic"
    priority                     = 100
    direction                    = "Outbound"
    access                       = "Allow"
    protocol                     = "*"
    source_port_range            = "*"
    destination_port_range       = "*"
    source_address_prefixes      = local.cluster_cidrs
    destination_address_prefixes = local.cluster_cidrs
  }
  security_rule {
    name                       = "AllowPrivateServicesTls"
    priority                   = 110
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefixes    = local.aks_cidrs
    destination_address_prefix = local.subnets.endpoints.cidr
  }
  security_rule {
    name                       = "AllowFirewallDns"
    priority                   = 120
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "53"
    source_address_prefixes    = local.aks_cidrs
    destination_address_prefix = azurerm_firewall.this.ip_configuration[0].private_ip_address
  }
  security_rule {
    name                       = "AllowWebThroughForcedRoute"
    priority                   = 130
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = ["80", "443"]
    source_address_prefixes    = local.aks_cidrs
    destination_address_prefix = "Internet"
  }
  security_rule {
    name                       = "DenyOtherOutbound"
    priority                   = 4000
    direction                  = "Outbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}
resource "azurerm_subnet_network_security_group_association" "aks" {
  for_each                  = toset(["system", "user"])
  subnet_id                 = azurerm_subnet.this[each.value].id
  network_security_group_id = azurerm_network_security_group.aks.id
}
