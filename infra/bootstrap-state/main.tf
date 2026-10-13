terraform {
  required_version = ">= 1.10.0, < 2.0.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "= 4.81.0"
    }
  }
  # Premier bootstrap local, puis migrer cet état dans un blob dédié (README).
}
provider "azurerm" {
  subscription_id                 = var.subscription_id
  tenant_id                       = var.tenant_id
  storage_use_azuread             = true
  resource_provider_registrations = "none"
  features {}
}
variable "subscription_id" { type = string }
variable "tenant_id" { type = string }
variable "storage_account_name" {
  type = string
  validation {
    condition     = can(regex("^[a-z0-9]{3,24}$", var.storage_account_name))
    error_message = "Nom Storage globalement unique : 3 à 24 caractères alphanumériques minuscules."
  }
}
variable "location" {
  type    = string
  default = "westeurope"
}
variable "resource_group_name" {
  type    = string
  default = "rg-tfstate-prod"
}
variable "existing_hub_endpoint_subnet_id" {
  type        = string
  description = "Sous-réseau du hub existant, accessible par le poste/runners de bootstrap."
}
variable "existing_blob_private_dns_zone_id" {
  type        = string
  description = "Zone privatelink.blob.core.windows.net préexistante et liée au hub ; ne pas dupliquer."
}
variable "state_principal_ids" {
  type        = set(string)
  description = "Object IDs opérateur de bootstrap et identité OIDC Terraform infra ; jamais build/sign."
  validation {
    condition     = length(var.state_principal_ids) > 0
    error_message = "Prévoir au moins un principal autorisé pour initialiser le conteneur."
  }
}
resource "azurerm_resource_group" "this" {
  name     = var.resource_group_name
  location = var.location
}
resource "azurerm_storage_account" "this" {
  name                             = var.storage_account_name
  resource_group_name              = azurerm_resource_group.this.name
  location                         = var.location
  account_tier                     = "Standard"
  account_replication_type         = "ZRS"
  min_tls_version                  = "TLS1_2"
  shared_access_key_enabled        = false
  default_to_oauth_authentication  = true
  public_network_access_enabled    = false
  allow_nested_items_to_be_public  = false
  cross_tenant_replication_enabled = false
  # Phase 3 / Trivy AZU-0012 : défense explicite, même avec accès public désactivé.
  network_rules {
    default_action = "Deny"
    bypass         = ["None"]
  }
  blob_properties {
    versioning_enabled = true
    delete_retention_policy { days = 30 }
    container_delete_retention_policy { days = 30 }
  }
  lifecycle { prevent_destroy = true }
}
resource "azurerm_private_endpoint" "blob" {
  name                = "pe-tfstate"
  resource_group_name = azurerm_resource_group.this.name
  location            = var.location
  subnet_id           = var.existing_hub_endpoint_subnet_id
  private_service_connection {
    name                           = "blob"
    private_connection_resource_id = azurerm_storage_account.this.id
    subresource_names              = ["blob"]
    is_manual_connection           = false
  }
  private_dns_zone_group {
    name                 = "blob"
    private_dns_zone_ids = [var.existing_blob_private_dns_zone_id]
  }
}
resource "azurerm_role_assignment" "state" {
  for_each             = var.state_principal_ids
  scope                = azurerm_storage_container.state.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = each.value
}
resource "azurerm_storage_container" "state" {
  name                  = "tfstate"
  storage_account_id    = azurerm_storage_account.this.id
  container_access_type = "private"
  # storage_account_id utilise ARM. Le backend utilise ensuite le data-plane privé.
  depends_on = [azurerm_private_endpoint.blob]
  lifecycle { prevent_destroy = true }
}
output "backend" {
  value = {
    resource_group_name  = azurerm_resource_group.this.name
    storage_account_name = azurerm_storage_account.this.name
    container_name       = azurerm_storage_container.state.name
    use_azuread_auth     = true
  }
}
