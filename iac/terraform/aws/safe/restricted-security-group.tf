# BENCH-IAC-006
resource "aws_security_group" "safe_sg" {
  name        = "safe-sg"
  description = "Allows SSH from internal CIDR"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
