# BENCH-IAC-037: Compounded inter-resource risk
# Tests: Inter-resource dependency analysis
# A security group allows all traffic → an RDS instance uses that SG →
# the RDS is publicly accessible. The scanner must trace the dependency
# chain to understand the compounded risk.

resource "aws_security_group" "chain_sg" {
  name        = "chain-open-sg"
  description = "Allows all inbound — part of compound risk"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_subnet_group" "chain_subnet" {
  name       = "chain-db-subnet"
  subnet_ids = ["subnet-12345", "subnet-67890"]
}

# This RDS instance is publicly accessible AND uses the wide-open SG
resource "aws_db_instance" "chain_rds" {
  identifier              = "compound-risk-db"
  allocated_storage       = 20
  engine                  = "mysql"
  engine_version          = "8.0"
  instance_class          = "db.t3.micro"
  db_name                 = "compoundriskdb"
  username                = "admin"
  password                = "CompoundRiskPassword!"
  publicly_accessible     = true
  vpc_security_group_ids  = [aws_security_group.chain_sg.id]
  db_subnet_group_name    = aws_db_subnet_group.chain_subnet.name
  storage_encrypted       = false
  skip_final_snapshot     = true
  backup_retention_period = 0
}

# An S3 bucket policy that references the RDS output
resource "aws_s3_bucket" "chain_backup" {
  bucket = "compound-risk-backups"
}

resource "aws_s3_bucket_policy" "chain_backup_policy" {
  bucket = aws_s3_bucket.chain_backup.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.chain_backup.arn}/*"
    }]
  })
}
