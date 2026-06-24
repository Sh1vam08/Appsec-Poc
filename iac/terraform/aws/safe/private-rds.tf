# BENCH-IAC-004
resource "aws_db_instance" "safe_rds" {
  allocated_storage    = 20
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro"
  db_name              = "safedb"
  username             = "admin"
  password             = "SecurePassword!987"
  publicly_accessible  = false
}
