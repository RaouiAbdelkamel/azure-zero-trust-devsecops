output "vnet_id" { value = azurerm_virtual_network.this.id }
output "system_subnet_id" { value = azurerm_subnet.this["system"].id }
output "user_subnet_id" { value = azurerm_subnet.this["user"].id }
output "endpoint_subnet_id" { value = azurerm_subnet.this["endpoints"].id }
output "runner_subnet_id" { value = azurerm_subnet.this["runners"].id }
output "route_table_id" { value = azurerm_route_table.aks.id }
output "aks_nsg_id" { value = azurerm_network_security_group.aks.id }
output "acr_dns_zone_id" { value = azurerm_private_dns_zone.this["acr"].id }
output "vault_dns_zone_id" { value = azurerm_private_dns_zone.this["vault"].id }
output "monitor_dns_zone_ids" {
  value = [for key in ["monitor", "oms", "ods", "agent", "blob"] : azurerm_private_dns_zone.this[key].id]
}
output "aks_dns_zone_id" { value = azurerm_private_dns_zone.this["aks"].id }
output "firewall_id" { value = azurerm_firewall.this.id }
output "firewall_public_ip" { value = azurerm_public_ip.firewall.ip_address }
