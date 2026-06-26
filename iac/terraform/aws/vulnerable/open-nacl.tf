# BENCH-IAC-033: NACL allowing all traffic + VPC without flow logs
# Tests: Network configuration analysis (IaC context)

resource "aws_network_acl" "vulnerable_nacl" {
  vpc_id = aws_vpc.vulnerable_vpc_network.id

  # Allow ALL inbound traffic
  ingress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  # Allow ALL outbound traffic
  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
}

resource "aws_vpc" "vulnerable_vpc_network" {
  cidr_block = "10.0.0.0/16"
  # No VPC flow logs configured
  # No DNS hostnames
  enable_dns_hostnames = false
}

# Security group allowing all ports from anywhere
resource "aws_security_group" "vulnerable_all_ports" {
  name        = "allow-all-ports"
  description = "Allows all traffic on all ports"
  vpc_id      = aws_vpc.vulnerable_vpc_network.id

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
