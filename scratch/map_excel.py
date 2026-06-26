import json
import pandas as pd
import re

# Load vulnerabilities
with open('benchmark-state/vulnerability_register.json', 'r') as f:
    vulns = json.load(f)['entries']

# Load Excel data
xls = pd.ExcelFile('Appsec.xlsx')
capabilities_by_sheet = {}
for sheet in xls.sheet_names:
    capabilities_by_sheet[sheet] = pd.read_excel(xls, sheet).iloc[2:, 0].dropna().tolist()

mapping = {}

def get_bench_ids(condition):
    return [v['benchmark_id'] for v in vulns if condition(v)]

for sheet, caps in capabilities_by_sheet.items():
    mapping[sheet] = {}
    for cap in caps:
        cap_lower = cap.lower()
        mapped_ids = []
        
        # Rule-based matching
        if "typosquatting" in cap_lower or "malicious package" in cap_lower:
            mapped_ids = get_bench_ids(lambda v: v['benchmark_id'] == 'BENCH-SCA-012')
        elif "license" in cap_lower:
            mapped_ids = get_bench_ids(lambda v: v['benchmark_id'] == 'BENCH-SCA-011')
        elif "dependency discovery" in cap_lower or "dependency analysis" in cap_lower:
            mapped_ids = get_bench_ids(lambda v: v['category'] == 'SCA' and v['benchmark_id'] not in ['BENCH-SCA-011', 'BENCH-SCA-012'])
        elif "static code analysis" in cap_lower or "source-to-sink" in cap_lower:
            mapped_ids = get_bench_ids(lambda v: v['category'] == 'SAST')
        elif "taint analysis" in cap_lower:
            mapped_ids = get_bench_ids(lambda v: v['category'] == 'SAST' and 'Injection' in str(v.get('subcategory', '')))
        elif "api security" in cap_lower:
            mapped_ids = get_bench_ids(lambda v: v['category'] == 'SAST' and '/api/' in str(v.get('endpoint', '')))
        elif "web application scanning" in cap_lower or "dast" in cap_lower:
            mapped_ids = get_bench_ids(lambda v: v['category'] == 'DAST')
        elif "api dast" in cap_lower:
            mapped_ids = get_bench_ids(lambda v: v['category'] == 'DAST' and '/api/' in str(v.get('endpoint', '')))
        elif "infrastructure" in cap_lower or "iac templates" in cap_lower or "misconfig" in cap_lower and sheet == "IaC Functional":
            mapped_ids = get_bench_ids(lambda v: v['benchmark_id'] == 'BENCH-IAC-001')
        elif "network" in cap_lower and sheet == "IaC Functional":
            mapped_ids = get_bench_ids(lambda v: v['benchmark_id'] == 'BENCH-IAC-002')
        elif "identity" in cap_lower or "iam" in cap_lower and sheet == "IaC Functional":
            mapped_ids = get_bench_ids(lambda v: v['benchmark_id'] == 'BENCH-IAC-003')
        elif "container misconfiguration" in cap_lower or "privilege" in cap_lower and sheet == "Container Functional":
            mapped_ids = get_bench_ids(lambda v: v['benchmark_id'] == 'BENCH-CONT-003')
        elif "secrets detection in container" in cap_lower:
            mapped_ids = get_bench_ids(lambda v: v['benchmark_id'] == 'BENCH-CONT-002')
        elif "network configuration analysis" in cap_lower and sheet == "Container Functional":
            mapped_ids = get_bench_ids(lambda v: v['benchmark_id'] == 'BENCH-CONT-001')
        elif "secrets detection" in cap_lower and sheet == "Secrets Functional":
            mapped_ids = get_bench_ids(lambda v: v['category'] == 'Secret')
        elif "entropy-based" in cap_lower and sheet == "Secrets Functional":
            mapped_ids = get_bench_ids(lambda v: v['category'] == 'Secret')
        
        # If no specific mapping but falls within category broadly
        if not mapped_ids:
            if "SCA" in sheet: mapped_ids = get_bench_ids(lambda v: v['category'] == 'SCA')
            elif "SAST" in sheet: mapped_ids = get_bench_ids(lambda v: v['category'] == 'SAST')
            elif "DAST" in sheet: mapped_ids = get_bench_ids(lambda v: v['category'] == 'DAST')
            elif "IaC" in sheet: mapped_ids = get_bench_ids(lambda v: v['category'] == 'IaC')
            elif "Container" in sheet: mapped_ids = get_bench_ids(lambda v: v['category'] == 'Container')
            elif "Secrets" in sheet: mapped_ids = get_bench_ids(lambda v: v['category'] == 'Secret')

        # Dedup and assign
        mapping[sheet][cap] = list(set(mapped_ids))

with open('benchmark-state/excel_capability_mapping.json', 'w') as f:
    json.dump(mapping, f, indent=2)

print("Generated benchmark-state/excel_capability_mapping.json")
