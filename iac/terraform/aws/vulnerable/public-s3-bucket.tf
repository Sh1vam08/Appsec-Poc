# BENCH-IAC-001
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "vulnerable-appsec-bucket"
}

resource "aws_s3_bucket_acl" "vulnerable_acl" {
  bucket = aws_s3_bucket.vulnerable_bucket.id
  acl    = "public-read"
}
