resource "azurerm_user_assigned_identity" "this" {
  for_each            = toset(["build", "sign", "ratify", "app"])
  name                = "id-${var.prefix}-${each.value}"
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags
}
resource "azurerm_federated_identity_credential" "github" {
  for_each = {
    build = var.github_build_environment
    sign  = var.github_sign_environment
  }
  name      = "github-${each.key}"
  parent_id = azurerm_user_assigned_identity.this[each.key].id
  audience  = ["api://AzureADTokenExchange"]
  issuer    = "https://token.actions.githubusercontent.com"
  subject   = "repo:${var.github_repository}:environment:${each.value}"
}
resource "azurerm_federated_identity_credential" "aks" {
  for_each = {
    ratify = "system:serviceaccount:${var.ratify_namespace}:${var.ratify_service_account}"
    app    = "system:serviceaccount:${var.workload_namespace}:fastapi"
  }
  name      = "aks-${each.key}"
  parent_id = azurerm_user_assigned_identity.this[each.key].id
  audience  = ["api://AzureADTokenExchange"]
  issuer    = var.aks_oidc_issuer_url
  subject   = each.value
}
resource "azurerm_role_assignment" "push" {
  for_each                         = toset(["build", "sign"])
  scope                            = var.acr_id
  role_definition_name             = "AcrPush"
  principal_id                     = azurerm_user_assigned_identity.this[each.value].principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
}
resource "azurerm_role_assignment" "verify_pull" {
  scope                            = var.acr_id
  role_definition_name             = "AcrPull"
  principal_id                     = azurerm_user_assigned_identity.this["ratify"].principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
}
# Notation : lecture de la clé publique/du certificat et opération sign uniquement.
# Aucun secret/get, decrypt, unwrap, export ou pouvoir de créer une clé.
resource "azurerm_role_definition" "sign" {
  name  = "${var.prefix}-notation-sign-only"
  scope = var.resource_group_id
  permissions {
    actions = []
    data_actions = [
      "Microsoft.KeyVault/vaults/keys/read",
      "Microsoft.KeyVault/vaults/keys/sign/action",
      "Microsoft.KeyVault/vaults/certificates/read"
    ]
  }
  assignable_scopes = [var.resource_group_id]
}
resource "azurerm_role_assignment" "sign" {
  scope                            = var.signing_vault_id
  role_definition_id               = azurerm_role_definition.sign.role_definition_resource_id
  principal_id                     = azurerm_user_assigned_identity.this["sign"].principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
}
# Ratify utilisera un trust store de certificats PUBLICS approuvés (Phase 4).
# Aucun accès Key Vault : certains plugins AKV exigent secret/get pour la chaîne,
# ce qui est incompatible avec notre séparation stricte des privilèges.
# L'identité app n'a aucun rôle par défaut. Ajouter uniquement les data-plane roles
# des ressources effectivement consommées (éventuellement secret individuel en Phase 4).
