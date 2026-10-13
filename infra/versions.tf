terraform {
  required_version = ">= 1.10.0, < 2.0.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "= 4.81.0"
    }
  }
  # Créé préalablement par bootstrap-state/ ; aucun compte/clé dans le code.
  backend "azurerm" {}
}

provider "azurerm" {
  subscription_id = var.subscription_id
  tenant_id       = var.tenant_id
  # Les providers sont enregistrés par l'équipe plateforme, pas par la CI.
  resource_provider_registrations = "none"
  storage_use_azuread             = true
  features {
    key_vault {
      purge_soft_delete_on_destroy    = false
      recover_soft_deleted_key_vaults = true
    }
  }
}
