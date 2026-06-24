# BENCH-IAC-003
resource "aws_db_instance" "vulnerable_rds" {
  allocated_storage    = 20
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro"
  db_name              = "vulnerabledb"
  username             = "admin"
  password             = "Password123!"
  publicly_accessible  = true
}
