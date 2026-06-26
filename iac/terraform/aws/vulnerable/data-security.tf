# BENCH-IAC-034: S3 bucket without server-side encryption
# Tests: Data security configuration analysis

resource "aws_s3_bucket" "vulnerable_no_encryption" {
  bucket = "vulnerable-no-encryption-bucket"
  # No server_side_encryption_configuration block
  # No versioning
  # No access logging
}

# BENCH-IAC-035: DynamoDB table without encryption
resource "aws_dynamodb_table" "vulnerable_dynamodb" {
  name         = "vulnerable-table"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  # No server_side_encryption block — uses default AWS-owned key only
  # No point-in-time recovery
  point_in_time_recovery {
    enabled = false
  }
}

# BENCH-IAC-036: Terraform backend without encryption
terraform {
  backend "s3" {
    bucket  = "my-terraform-state"
    key     = "state/terraform.tfstate"
    region  = "us-east-1"
    encrypt = false  # State file stored unencrypted!
    # No DynamoDB table for state locking
    # No versioning on state bucket
  }
}
