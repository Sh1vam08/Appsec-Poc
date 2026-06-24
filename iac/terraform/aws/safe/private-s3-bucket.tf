# BENCH-IAC-002
resource "aws_s3_bucket" "safe_bucket" {
  bucket = "safe-appsec-bucket"
}

resource "aws_s3_bucket_acl" "safe_acl" {
  bucket = aws_s3_bucket.safe_bucket.id
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "safe_block" {
  bucket = aws_s3_bucket.safe_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
