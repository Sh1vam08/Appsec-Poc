# BENCH-IAC-041: Drift example — TF definition says private, state says public
# Tests: Configuration drift analysis
#
# This .tf file defines the RDS as NOT publicly accessible,
# but the companion .tfstate file shows it deployed as publicly_accessible = true.
# A scanner should detect this drift between desired and actual state.

resource "aws_db_instance" "drift_example_rds" {
  identifier           = "drift-example-db"
  allocated_storage    = 20
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro"
  db_name              = "driftdb"
  username             = "admin"
  password             = "DriftExamplePass!"
  publicly_accessible  = false  # Definition says PRIVATE
  storage_encrypted    = true   # Definition says ENCRYPTED
}
