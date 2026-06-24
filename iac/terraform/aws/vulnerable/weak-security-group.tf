# BENCH-IAC-005
resource "aws_security_group" "vulnerable_sg" {
  name        = "vulnerable-sg"
  description = "Allows SSH from anywhere"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
