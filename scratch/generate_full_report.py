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
md += 'This report evaluates Snyk against ALL capabilities defined in Appsec.xlsx.\n\n'

for cat, r in results.items():
    tpr = (r['TP'] / (r['TP'] + r['FN']) * 100) if (r['TP'] + r['FN']) > 0 else 0
    fpr = (r['FP'] / (r['FP'] + r['TN']) * 100) if (r['FP'] + r['TN']) > 0 else 0
    
    md += f'## {cat} Security\n'
    md += f'**KPIs:**\n'
    md += f'- **Coverage (True Positive Rate):** {tpr:.1f}%\n'
    md += f'- **False Positive Rate:** {fpr:.1f}%\n'
    md += f'- **True Positives (TP):** {r["TP"]}\n'
    md += f'- **False Negatives (FN - Undetected):** {r["FN"]}\n'
    md += f'- **True Negatives (TN):** {r["TN"]}\n'
    md += f'- **False Positives (FP):** {r["FP"]}\n\n'
    
    md += '### Capability Mapping Checklist\n'
    
    cat_key = map_cat.get(cat)
    if cat_key and cat_key in caps:
        cap_dict = caps[cat_key]
        for cid, desc in cap_dict.items():
            if cid in r['caps_detected']:
                md += f'- [x] **{cid}**: {desc} *(PRESENT)*\n'
            elif cid in r['caps_missed']:
                md += f'- [ ] **{cid}**: {desc} *(UNDETECTED - Vulnerability Missed)*\n'
            else:
                md += f'- [ ] **{cid}**: {desc} *(UNDETECTED / NO DATA)*\n'
    
    md += '\n---\n\n'

with open('C:/Users/ABCD/.gemini/antigravity-ide/brain/7db8bd5b-13ff-4134-aaa7-b564d9f5fb33/snyk_benchmark_report.md', 'w', encoding='utf-8') as f:
    f.write(md)
