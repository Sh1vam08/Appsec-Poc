# BENCH-IAC-007
resource "aws_iam_role_policy" "vulnerable_policy" {
  name = "vulnerable_policy"
  role = "example_role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = ["*"]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}
