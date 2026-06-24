# BENCH-IAC-010
resource "aws_ebs_volume" "safe_volume" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = true
}
