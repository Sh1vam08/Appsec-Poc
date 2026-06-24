# BENCH-IAC-012
resource "aws_s3_bucket" "log_bucket" {
  bucket = "safe-log-bucket"
}

resource "aws_s3_bucket" "safe_logging" {
  bucket = "safe-logging-bucket"
}

resource "aws_s3_bucket_logging" "safe_logging_config" {
  bucket        = aws_s3_bucket.safe_logging.id
  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "log/"
}
