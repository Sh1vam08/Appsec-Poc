# Vulnerable IAM Policy (Over-privileged)
resource "aws_iam_role" "benchmark_role" {
  name = "benchmark_admin_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "benchmark_policy" {
  name = "benchmark_admin_policy"
  role = aws_iam_role.benchmark_role.id

  # SAST/IaC Vulnerability Sink: Wildcard privileges
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "*"
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}
