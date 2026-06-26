import json

new_entries = [
    {
        "benchmark_id": "BENCH-IAC-001",
        "capability_id": "CAP-IAC-S3-001",
        "category": "IaC",
        "subcategory": "Public S3 Bucket",
        "variant": "vulnerable",
        "cwe": "CWE-16",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "severity": "HIGH",
        "file": "infrastructure/main.tf",
        "line": 6,
        "endpoint": None,
        "reachable": True,
        "exploitable": True
    },
    {
        "benchmark_id": "BENCH-IAC-002",
        "capability_id": "CAP-IAC-SG-001",
        "category": "IaC",
        "subcategory": "Open Security Group",
        "variant": "vulnerable",
        "cwe": "CWE-16",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "severity": "HIGH",
        "file": "infrastructure/main.tf",
        "line": 19,
        "endpoint": None,
        "reachable": True,
        "exploitable": True
    },
    {
        "benchmark_id": "BENCH-IAC-003",
        "capability_id": "CAP-IAC-IAM-001",
        "category": "IaC",
        "subcategory": "Overly Permissive IAM Role",
        "variant": "vulnerable",
        "cwe": "CWE-16",
        "owasp_category": "A01:2021-Broken Access Control",
        "severity": "HIGH",
        "file": "infrastructure/main.tf",
        "line": 39,
        "endpoint": None,
        "reachable": True,
        "exploitable": True
    },
    {
        "benchmark_id": "BENCH-CONT-001",
        "capability_id": "CAP-CONT-PORT-001",
        "category": "Container",
        "subcategory": "Exposed Sensitive Port",
        "variant": "vulnerable",
        "cwe": "CWE-16",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "severity": "MEDIUM",
        "file": "Dockerfile",
        "line": 26,
        "endpoint": None,
        "reachable": True,
        "exploitable": True
    },
    {
        "benchmark_id": "BENCH-CONT-002",
        "capability_id": "CAP-CONT-SEC-001",
        "category": "Container",
        "subcategory": "Secret in Environment Variable",
        "variant": "vulnerable",
        "cwe": "CWE-798",
        "owasp_category": "A07:2021-Identification and Authentication Failures",
        "severity": "HIGH",
        "file": "Dockerfile",
        "line": 29,
        "endpoint": None,
        "reachable": True,
        "exploitable": True
    },
    {
        "benchmark_id": "BENCH-CONT-003",
        "capability_id": "CAP-CONT-ROOT-001",
        "category": "Container",
        "subcategory": "Running as Root",
        "variant": "vulnerable",
        "cwe": "CWE-250",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "severity": "HIGH",
        "file": "Dockerfile",
        "line": 36,
        "endpoint": None,
        "reachable": True,
        "exploitable": True
    },
    {
        "benchmark_id": "BENCH-SCA-011",
        "capability_id": "CAP-SCA-LIC-001",
        "category": "SCA",
        "subcategory": "Restrictive License (AGPL)",
        "variant": "vulnerable",
        "cwe": "CWE-0",
        "owasp_category": "A06:2021-Vulnerable and Outdated Components",
        "severity": "MEDIUM",
        "file": "pom.xml",
        "line": None,
        "endpoint": None,
        "reachable": True,
        "exploitable": True
    },
    {
        "benchmark_id": "BENCH-SCA-012",
        "capability_id": "CAP-SCA-TYPO-001",
        "category": "SCA",
        "subcategory": "Typosquatting/Malicious Package",
        "variant": "vulnerable",
        "cwe": "CWE-1357",
        "owasp_category": "A06:2021-Vulnerable and Outdated Components",
        "severity": "CRITICAL",
        "file": "frontend/package.json",
        "line": 4,
        "endpoint": None,
        "reachable": True,
        "exploitable": True
    },
    {
        "benchmark_id": "BENCH-SEC-006",
        "capability_id": "CAP-SEC-AWS-002",
        "category": "Secret",
        "subcategory": "Hardcoded AWS Key",
        "variant": "vulnerable",
        "cwe": "CWE-798",
        "owasp_category": "A07:2021-Identification and Authentication Failures",
        "severity": "CRITICAL",
        "file": "infrastructure/terraform.tfvars",
        "line": 2,
        "endpoint": None,
        "reachable": True,
        "exploitable": True
    },
    {
        "benchmark_id": "BENCH-SEC-007",
        "capability_id": "CAP-SEC-SLACK-001",
        "category": "Secret",
        "subcategory": "Hardcoded Slack Webhook",
        "variant": "vulnerable",
        "cwe": "CWE-798",
        "owasp_category": "A07:2021-Identification and Authentication Failures",
        "severity": "HIGH",
        "file": "src/main/resources/application.properties",
        "line": 56,
        "endpoint": None,
        "reachable": True,
        "exploitable": True
    }
]

with open('benchmark-state/vulnerability_register.json', 'r') as f:
    data = json.load(f)

# avoid duplicates
existing = {x['benchmark_id'] for x in data['entries']}
for entry in new_entries:
    if entry['benchmark_id'] not in existing:
        data['entries'].append(entry)

with open('benchmark-state/vulnerability_register.json', 'w') as f:
    json.dump(data, f, indent=2)

print("Updated vulnerability_register.json")
