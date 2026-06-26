# Vulnerable Security Group
resource "aws_security_group" "benchmark_sg" {
  name        = "benchmark_public_sg"
  description = "Security group for benchmark application"

  # SAST/IaC Vulnerability Sink: SSH open to the world
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # SAST/IaC Vulnerability Sink: RDP open to the world
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
