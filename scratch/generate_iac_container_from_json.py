import json

with open('snyk_results.json', 'r', encoding='utf-8') as f:
    results = json.load(f)

with open('benchmark-state/excel_capability_mapping.json', 'r', encoding='utf-8') as f:
    all_caps = json.load(f)

MANUAL_CONTAINER = [
    "Image integrity verification",
    "Software provenance tracking",
    "Registry exposure and access analysis",
    "Container runtime behavior analysis"
]

MANUAL_IAC = [
    "Inter-resource dependency analysis",
    "Configuration drift analysis",
    "Template design/root cause analysis"
]

def generate_report(cat_name, manual_list, cap_key):
    r = results.get(cat_name, {})
    detected_bids = set(r.get('bench_detected', []))
    
    caps = all_caps.get(cap_key, {})
    
    md = f'# Snyk {cat_name} Analysis Report (Code-Verified Only)\n\n'
    md += 'This report evaluates Snyk strictly against capabilities that can be proven via code analysis.\n\n'
    md += f'## {cat_name} Capability Checklist\n'
    
    for cap_name, bench_ids in caps.items():
        if cap_name in ["KPI Metrices", "Metric", "Scan Time", "Detection Coverage", "Accuracy", "False Negatives", "Layer Coverage", "Base Image Accuracy", "Cost", "Misconfig Detection"]:
            continue
            
        if cap_name in manual_list:
            md += f'- **{cap_name}**: Manual Verification Required \n  *Evidence: Cannot evaluate UI/Platform features via basic scan data.*\n'
            continue
            
        num_total = len(bench_ids)
        detected_intersection = detected_bids.intersection(bench_ids)
        num_detected = len(detected_intersection)
        
        if num_total == 0:
            status = 'Not Present'
            evidence = 'No test scenarios seeded for this capability.'
        elif num_detected == 0:
            status = 'Not Present'
            evidence = 'No vulnerabilities detected for this capability.'
        elif num_detected == num_total:
            status = 'Present'
            evidence = f'Detected {num_detected}/{num_total} seeded vulnerabilities.'
        else:
            status = 'Present (Partially)'
            evidence = f'Detected {num_detected}/{num_total} seeded vulnerabilities.'
            
        md += f'- **{cap_name}**: {status} \n  *Evidence: {evidence}*\n'
        
    with open(f'C:/Users/ABCD/.gemini/antigravity-ide/brain/7db8bd5b-13ff-4134-aaa7-b564d9f5fb33/Snyk_{cat_name}_Analysis_Verified.md', 'w', encoding='utf-8') as f:
        f.write(md)
    print(f"Generated {cat_name}")

generate_report('CONTAINER', MANUAL_CONTAINER, 'Container Functional')
generate_report('IAC', MANUAL_IAC, 'IaC Functional')
