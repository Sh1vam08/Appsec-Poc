# BENCH-IAC-038: Repeated pattern of same misconfiguration
# Tests: Template design/root cause analysis
# Three S3 buckets all missing encryption, versioning, and logging.
# A scanner should identify this as a systemic template-level issue.

resource "aws_s3_bucket" "pattern_bucket_1" {
  bucket = "repeated-pattern-bucket-1"
  # No encryption, no versioning, no logging
}

resource "aws_s3_bucket" "pattern_bucket_2" {
  bucket = "repeated-pattern-bucket-2"
  # No encryption, no versioning, no logging
}

resource "aws_s3_bucket" "pattern_bucket_3" {
  bucket = "repeated-pattern-bucket-3"
  # No encryption, no versioning, no logging
}

# Three EBS volumes all missing encryption
resource "aws_ebs_volume" "pattern_vol_1" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = false
}

resource "aws_ebs_volume" "pattern_vol_2" {
  availability_zone = "us-east-1b"
  size              = 40
  encrypted         = false
}

resource "aws_ebs_volume" "pattern_vol_3" {
  availability_zone = "us-east-1c"
  size              = 40
  encrypted         = false
}
