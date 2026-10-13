variable "subscription_id" {
  type        = string
  description = "Subscription cible ; identifiant public, pas un secret."
}
variable "tenant_id" {
  type = string
}
variable "prefix" {
  type    = string
  default = "ztprod"
  validation {
    condition     = can(regex("^[a-z][a-z0-9]{2,6}$", var.prefix))
    error_message = "3 à 7 caractères alphanumériques minuscules, commençant par une lettre."
  }
}
variable "unique_suffix" {
  type        = string
  description = "Suffixe public pour les noms ACR/Key Vault globalement uniques."
  validation {
    condition     = can(regex("^[a-z0-9]{6,8}$", var.unique_suffix))
    error_message = "6 à 8 caractères alphanumériques minuscules."
  }
}
variable "location" {
  type    = string
  default = "westeurope"
  validation {
    condition     = contains(["westeurope", "northeurope", "francecentral"], var.location)
    error_message = "Ce socle Azure public est prévu pour westeurope, northeurope ou francecentral."
  }
}
variable "kubernetes_version" {
  type        = string
  description = "Version GA exacte x.y.z, confirmée disponible dans la région avant plan."
  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+$", var.kubernetes_version))
    error_message = "Indiquer une version GA exacte x.y.z."
  }
}
variable "security_admin_group_object_id" {
  type        = string
  description = "Groupe Entra d'exploitation, idéalement activable via PIM. Aucun compte local AKS."
}
variable "github_repository" {
  type        = string
  description = "Dépôt autorisé, forme organisation/depot. Aucun wildcard OIDC."
  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "Format attendu : organisation/depot."
  }
}
variable "github_build_environment" {
  type    = string
  default = "build-production"
}
variable "github_sign_environment" {
  type    = string
  default = "sign-production"
  validation {
    condition     = var.github_sign_environment != var.github_build_environment
    error_message = "Build et signature doivent utiliser des environnements GitHub distincts."
  }
}
variable "workload_namespace" {
  type    = string
  default = "fastapi"
  validation {
    condition     = length(var.workload_namespace) <= 63 && can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", var.workload_namespace))
    error_message = "Le namespace doit être un nom Kubernetes DNS valide."
  }
}
variable "ratify_namespace" {
  type    = string
  default = "gatekeeper-system"
}
variable "ratify_service_account" {
  type        = string
  default     = "ratify"
  description = "Doit correspondre au ServiceAccount du chart installé en Phase 4."
}
variable "system_vm_size" {
  type    = string
  default = "Standard_D4s_v5"
}
variable "user_vm_size" {
  type    = string
  default = "Standard_D4s_v5"
}
variable "tags" {
  type = map(string)
  default = {
    environment = "production"
    managed_by  = "terraform"
    workload    = "fastapi"
  }
}
