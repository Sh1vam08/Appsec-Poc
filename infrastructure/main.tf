provider "aws" {
  region = "us-east-1"
}

# BENCH-IAC-001: Publicly accessible S3 bucket (Misconfiguration detection)
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "appsec-benchmark-public-data"
}

resource "aws_s3_bucket_acl" "vulnerable_bucket_acl" {
  bucket = aws_s3_bucket.vulnerable_bucket.id
  acl    = "public-read"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "unencrypted_bucket" {
  bucket = aws_s3_bucket.vulnerable_bucket.id
  # Intentional missing encryption
}

# BENCH-IAC-002: Security Group allowing unrestricted inbound access
resource "aws_security_group" "vulnerable_sg" {
  name        = "allow_all_traffic"
  description = "Allow all inbound traffic"

  ingress {
    description = "Allow all"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# BENCH-IAC-003: Overly permissive IAM Role
resource "aws_iam_role" "vulnerable_role" {
  name = "AdminRole"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "AWS": "*"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_policy_attachment" "vulnerable_attachment" {
  name       = "admin_attachment"
  roles      = [aws_iam_role.vulnerable_role.name]
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
