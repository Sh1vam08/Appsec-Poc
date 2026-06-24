# BENCH-IAC-011
resource "aws_s3_bucket" "vulnerable_no_logging" {
  bucket = "vulnerable-no-logging-bucket"
}
