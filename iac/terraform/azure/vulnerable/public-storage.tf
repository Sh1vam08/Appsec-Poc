# BENCH-IAC-021: Azure Storage Account publicly accessible
# Tests: Infrastructure configuration analysis, Resource exposure analysis

resource "azurerm_resource_group" "vulnerable_rg" {
  name     = "vulnerable-resources"
  location = "East US"
}

# Public blob storage — no private endpoint, HTTP allowed
resource "azurerm_storage_account" "vulnerable_storage" {
  name                     = "vulnstorage"
  resource_group_name      = azurerm_resource_group.vulnerable_rg.name
  location                 = azurerm_resource_group.vulnerable_rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # Insecure: allows HTTP access
  enable_https_traffic_only = false

  # Insecure: public network access enabled
  public_network_access_enabled = true

  # Insecure: no encryption with customer-managed key
  # Uses only Microsoft-managed keys
}

# Public blob container
resource "azurerm_storage_container" "vulnerable_container" {
  name                  = "public-data"
  storage_account_name  = azurerm_storage_account.vulnerable_storage.name
  container_access_type = "blob"  # Publicly accessible
}
