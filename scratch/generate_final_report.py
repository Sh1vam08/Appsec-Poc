import json
with open('snyk_results.json', 'r') as f: results = json.load(f)
with open('benchmark-state/excel_capability_mapping.json', 'r', encoding='utf-8') as f: caps = json.load(f)

map_cat = {
    'SAST': 'SAST Functional',
    'SCA': 'SCA Functional',
    'IAC': 'IaC Functional',
    'CONTAINER': 'Container Functional',
    'SECRETS': 'Secrets Functional'
}

md = '# Snyk Comprehensive Evaluation Report\n\n'
md += 'This report evaluates Snyk against the capabilities and specific KPIs defined in Appsec.xlsx.\n\n'

for cat, r in results.items():
    tp = r['TP']
    fn = r['FN']
    fp = r['FP']
    tn = r['TN']
    
    total_seeded = tp + fn
    total_findings = tp + fp
    
    detection_coverage = (tp / total_seeded * 100) if total_seeded > 0 else 0
    accuracy = (tp / total_findings * 100) if total_findings > 0 else 0
    miss_rate = (fn / total_seeded * 100) if total_seeded > 0 else 0
    
    md += f'## {cat} Security\n'
    md += f'### KPI Metrices\n'
    md += f'- **Detection Coverage:** {detection_coverage:.1f}%\n'
    md += f'- **Accuracy:** {accuracy:.1f}%\n'
    md += f'- **False Negatives:** {miss_rate:.1f}%\n'
    md += f'- **Scan Time:** N/A\n'
    md += f'- **Cost:** N/A\n'
    
    if cat == 'SAST':
        md += f'- **Language Coverage:** N/A\n'
        md += f'- **Reachability Analysis Accuracy:** N/A\n'
        md += f'- **Remediation Guidance Efficacy:** N/A\n'
    elif cat == 'SCA':
        md += f'- **Language Coverage:** N/A\n'
        md += f'- **Exploitability Context Accuracy:** N/A\n'
        md += f'- **Transitive Dependency Accuracy:** N/A\n'
    elif cat == 'CONTAINER':
        md += f'- **Layer Coverage:** N/A\n'
        md += f'- **Base Image Accuracy:** N/A\n'
        
    md += '\n### Capability Checklist\n'
    
    cat_key = map_cat.get(cat)
    if cat_key and cat_key in caps:
        cap_dict = caps[cat_key]
        for cap_name, bench_ids in cap_dict.items():
            num_total = len(bench_ids)
            num_detected = sum(1 for bid in bench_ids if bid in r['bench_detected'])
            
            if num_total == 0 or num_detected == 0:
                status = 'Not Avaialabe'
            elif num_detected == num_total:
                status = 'Available'
            else:
                status = 'Partially Available'
                
            md += f'- **{cap_name}**: {status}\n'
    
    md += '\n---\n\n'

with open('C:/Users/ABCD/.gemini/antigravity-ide/brain/7db8bd5b-13ff-4134-aaa7-b564d9f5fb33/snyk_benchmark_report.md', 'w', encoding='utf-8') as f:
    f.write(md)
