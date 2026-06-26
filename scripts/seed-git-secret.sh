#!/bin/bash
# BENCH-SECRET-033: Git history burial script
# Tests: Secrets detection in version control history
#
# This script commits a secret into git, then removes it in the next commit.
# A scanner must inspect the git log/diff history to find the buried secret.
#
# Usage: Run this script in the repo root to seed the git history.

echo "=== Seeding secret into git history ==="

# Create a temporary file with a real-looking secret
cat > .temp-api-config.json << 'EOF'
{
  "production": {
    "stripe_key": "sk_live_51JvT9Z2eZvKYlo2CUzRealProductionKey",
    "database_password": "RealProdDBPassword2024!",
    "jwt_signing_key": "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgw",
    "sendgrid_api_key": "SG.RealSendGridAPIKeyThatWasBuried.InGitHistory"
  }
}
EOF

# Commit the secret
git add .temp-api-config.json
git commit -m "feat: add production API configuration"

# Now remove it (but it's still in git history!)
rm .temp-api-config.json
git add .temp-api-config.json
git commit -m "chore: remove temporary config file"

echo "=== Secret is now buried in git history ==="
echo "Run 'git log --all --diff-filter=D -- .temp-api-config.json' to verify"
