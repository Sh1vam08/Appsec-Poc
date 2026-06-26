# Vulnerable S3 Bucket
resource "aws_s3_bucket" "benchmark_data" {
  bucket = "appsec-benchmark-data-bucket"
  
  # SAST/IaC Vulnerability Sink: Public ACL
  acl    = "public-read"

  tags = {
    Name        = "Benchmark Data Bucket"
    Environment = "Dev"
  }
}

# The bucket intentionally lacks:
# - aws_s3_bucket_public_access_block
# - aws_s3_bucket_server_side_encryption_configuration
