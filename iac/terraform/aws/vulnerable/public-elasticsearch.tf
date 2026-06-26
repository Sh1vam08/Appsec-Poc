# BENCH-IAC-031: Publicly exposed Elasticsearch domain
# Tests: Resource exposure analysis

resource "aws_elasticsearch_domain" "vulnerable_es" {
  domain_name           = "vulnerable-search"
  elasticsearch_version = "7.10"

  cluster_config {
    instance_type = "t3.small.elasticsearch"
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  # No encryption at rest
  encrypt_at_rest {
    enabled = false
  }

  # No node-to-node encryption
  node_to_node_encryption {
    enabled = false
  }

  # Public access policy — anyone can read/write
  access_policies = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "es:*"
      Resource  = "arn:aws:es:us-east-1:123456789012:domain/vulnerable-search/*"
    }]
  })
}

# BENCH-IAC-032: Sensitive Terraform output
# Tests: Resource exposure analysis
output "database_password" {
  value     = "ProductionDBPassword123!"
  sensitive = false  # Should be true! Password printed to stdout
}

output "api_secret_key" {
  value     = "sk_live_OutputtedAPIKey12345"
  sensitive = false
}
