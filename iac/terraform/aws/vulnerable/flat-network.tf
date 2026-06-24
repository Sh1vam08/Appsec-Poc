# BENCH-IAC-013
resource "aws_vpc" "vulnerable_vpc" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "vulnerable_subnet" {
  vpc_id     = aws_vpc.vulnerable_vpc.id
  cidr_block = "10.0.0.0/16"
}
