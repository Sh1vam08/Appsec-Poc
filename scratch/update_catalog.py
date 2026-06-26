import json

new_entries = [
    {
        "benchmark_id": "BENCH-IAC-001",
        "subcategory": "Public S3 Bucket",
        "variant": "vulnerable",
        "severity": "HIGH",
        "cwe": "CWE-16",
        "file": "infrastructure/main.tf",
        "endpoint": None,
        "category": "IaC"
    },
    {
        "benchmark_id": "BENCH-IAC-002",
        "subcategory": "Open Security Group",
        "variant": "vulnerable",
        "severity": "HIGH",
        "cwe": "CWE-16",
        "file": "infrastructure/main.tf",
        "endpoint": None,
        "category": "IaC"
    },
    {
        "benchmark_id": "BENCH-IAC-003",
        "subcategory": "Overly Permissive IAM Role",
        "variant": "vulnerable",
        "severity": "HIGH",
        "cwe": "CWE-16",
        "file": "infrastructure/main.tf",
        "endpoint": None,
        "category": "IaC"
    },
    {
        "benchmark_id": "BENCH-CONT-001",
        "subcategory": "Exposed Sensitive Port",
        "variant": "vulnerable",
        "severity": "MEDIUM",
        "cwe": "CWE-16",
        "file": "Dockerfile",
        "endpoint": None,
        "category": "Container"
    },
    {
        "benchmark_id": "BENCH-CONT-002",
        "subcategory": "Secret in Environment Variable",
        "variant": "vulnerable",
        "severity": "HIGH",
        "cwe": "CWE-798",
        "file": "Dockerfile",
        "endpoint": None,
        "category": "Container"
    },
    {
        "benchmark_id": "BENCH-CONT-003",
        "subcategory": "Running as Root",
        "variant": "vulnerable",
        "severity": "HIGH",
        "cwe": "CWE-250",
        "file": "Dockerfile",
        "endpoint": None,
        "category": "Container"
    },
    {
        "benchmark_id": "BENCH-SCA-011",
        "subcategory": "Restrictive License (AGPL)",
        "variant": "vulnerable",
        "severity": "MEDIUM",
        "cwe": "CWE-0",
        "file": "pom.xml",
        "endpoint": None,
        "category": "SCA"
    },
    {
        "benchmark_id": "BENCH-SCA-012",
        "subcategory": "Typosquatting/Malicious Package",
        "variant": "vulnerable",
        "severity": "CRITICAL",
        "cwe": "CWE-1357",
        "file": "frontend/package.json",
        "endpoint": None,
        "category": "SCA"
    },
    {
        "benchmark_id": "BENCH-SEC-006",
        "subcategory": "Hardcoded AWS Key",
        "variant": "vulnerable",
        "severity": "CRITICAL",
        "cwe": "CWE-798",
        "file": "infrastructure/terraform.tfvars",
        "endpoint": None,
        "category": "Secret"
    },
    {
        "benchmark_id": "BENCH-SEC-007",
        "subcategory": "Hardcoded Slack Webhook",
        "variant": "vulnerable",
        "severity": "HIGH",
        "cwe": "CWE-798",
        "file": "src/main/resources/application.properties",
        "endpoint": None,
        "category": "Secret"
    }
]

with open('benchmark-state/benchmark_catalog.json', 'r') as f:
    data = json.load(f)

for entry in new_entries:
    cat = entry.pop('category')
    
    # if category doesn't exist, create it
    if cat not in data['categories']:
        data['categories'][cat] = {"count": 0, "scenarios": []}
    
    existing = {x['benchmark_id'] for x in data['categories'][cat]['scenarios']}
    if entry['benchmark_id'] not in existing:
        data['categories'][cat]['scenarios'].append(entry)
        data['categories'][cat]['count'] += 1
        data['summary']['total_scenarios'] += 1

with open('benchmark-state/benchmark_catalog.json', 'w') as f:
    json.dump(data, f, indent=2)

print("Updated benchmark_catalog.json")
