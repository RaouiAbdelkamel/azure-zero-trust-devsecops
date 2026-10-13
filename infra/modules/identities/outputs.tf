output "client_ids" {
  value = { for name, identity in azurerm_user_assigned_identity.this : name => identity.client_id }
}
