# BENCH-IAC-009
resource "aws_ebs_volume" "vulnerable_volume" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = false
}
