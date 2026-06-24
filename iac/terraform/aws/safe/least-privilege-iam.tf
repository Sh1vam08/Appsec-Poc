# BENCH-IAC-008
resource "aws_iam_role_policy" "safe_policy" {
  name = "safe_policy"
  role = "example_role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Effect   = "Allow"
        Resource = "arn:aws:s3:::safe-appsec-bucket/*"
      }
    ]
  })
}
