# BENCH-IAC-029: IAM cross-account trust without external ID
# Tests: Identity and access configuration analysis (IaC context)

# Wildcard assume role — any AWS account can assume this role
resource "aws_iam_role" "vulnerable_cross_account" {
  name = "vulnerable-cross-account-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { AWS = "*" }  # Any AWS account can assume this role!
        # No Condition block with ExternalId — missing confused deputy protection
      }
    ]
  })
}

# Attach admin access to the cross-account role
resource "aws_iam_role_policy_attachment" "cross_account_admin" {
  role       = aws_iam_role.vulnerable_cross_account.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# BENCH-IAC-030: IAM user with inline admin policy and access keys
resource "aws_iam_user" "vulnerable_user" {
  name = "vulnerable-admin-user"
}

resource "aws_iam_user_policy" "admin_inline" {
  name = "inline-admin"
  user = aws_iam_user.vulnerable_user.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action   = ["*"]
      Effect   = "Allow"
      Resource = "*"
    }]
  })
}

resource "aws_iam_access_key" "vulnerable_key" {
  user = aws_iam_user.vulnerable_user.name
  # Access keys for IAM users with admin — high risk
}
