# BENCH-IAC-028: Lambda function without VPC
# Tests: Misconfiguration detection (IaC)

resource "aws_lambda_function" "vulnerable_lambda" {
  function_name = "vulnerable-lambda"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"
  filename      = "lambda.zip"

  # No VPC configuration — function runs outside VPC
  # No encryption configuration
  # No dead letter queue
  # No reserved concurrency limits

  environment {
    variables = {
      DB_PASSWORD = "LambdaDBPassword123!"  # Hardcoded secret
      API_KEY     = "sk_live_LambdaAPIKey12345"
    }
  }
}

resource "aws_iam_role" "lambda_role" {
  name = "vulnerable-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

# Overly permissive Lambda execution policy
resource "aws_iam_role_policy" "lambda_policy" {
  name = "lambda-full-access"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action   = ["*"]
      Effect   = "Allow"
      Resource = "*"
    }]
  })
}
