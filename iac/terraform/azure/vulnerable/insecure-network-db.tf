# BENCH-IAC-022: Azure Network Security Group allowing all inbound traffic
# Tests: Network configuration analysis (IaC context)

resource "azurerm_network_security_group" "vulnerable_nsg" {
  name                = "vulnerable-nsg"
  location            = "East US"
  resource_group_name = "vulnerable-resources"

  # Allow ALL inbound traffic from any source
  security_rule {
    name                       = "AllowAllInbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# BENCH-IAC-023: Azure SQL Database with no auditing and public access
# Tests: Data security configuration analysis, Misconfiguration detection

resource "azurerm_mssql_server" "vulnerable_sql" {
  name                         = "vulnerable-sql-server"
  resource_group_name          = "vulnerable-resources"
  location                     = "East US"
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "P@ssw0rd123!"  # Hardcoded password

  public_network_access_enabled = true  # Publicly accessible
}

# Allow all Azure services — overly permissive
resource "azurerm_mssql_firewall_rule" "vulnerable_fw" {
  name             = "AllowAllAzure"
  server_id        = azurerm_mssql_server.vulnerable_sql.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"
}
