import json
with open('snyk_results.json', 'r') as f: results = json.load(f)
with open('benchmark-state/excel_capability_mapping.json', 'r', encoding='utf-8') as f: caps = json.load(f)

cap_dict = {}
for category, items_dict in caps.items():
    if isinstance(items_dict, dict):
        for cap_id, req in items_dict.items():
            cap_dict[cap_id] = req

md = '# Snyk Benchmark Evaluation Report\n\n'
md += 'This report evaluates Snyk against the Enterprise AppSec Benchmark Suite based on the capabilities defined in Appsec.xlsx.\n\n'

for cat, r in results.items():
    tpr = (r['TP'] / (r['TP'] + r['FN']) * 100) if (r['TP'] + r['FN']) > 0 else 0
    fpr = (r['FP'] / (r['FP'] + r['TN']) * 100) if (r['FP'] + r['TN']) > 0 else 0
    
    md += f'## {cat} Security\n'
    md += f'**KPIs:**\n'
    md += f'- **Coverage (True Positive Rate):** {tpr:.1f}%\n'
    md += f'- **False Positive Rate:** {fpr:.1f}%\n'
    md += f'- **True Positives (TP):** {r["TP"]}\n'
    md += f'- **False Negatives (FN):** {r["FN"]}\n'
    md += f'- **True Negatives (TN):** {r["TN"]}\n'
    md += f'- **False Positives (FP):** {r["FP"]}\n\n'
    
    md += '### Capabilities Successfully Detected (True Positives)\n'
    if r['caps_detected']:
        for cid in sorted(r['caps_detected']):
            desc = cap_dict.get(cid, 'Unknown Capability Description')
            md += f'- **{cid}**: {desc}\n'
    else:
        md += '- None detected in this category.\n'
        
    md += '\n### Capabilities Missed (False Negatives)\n'
    if r['caps_missed']:
        for cid in sorted(r['caps_missed']):
            desc = cap_dict.get(cid, 'Unknown Capability Description')
            md += f'- **{cid}**: {desc}\n'
    else:
        md += '- Perfect coverage! No capabilities missed.\n'
    md += '\n---\n\n'

with open('snyk_evaluation_report.md', 'w', encoding='utf-8') as f:
    f.write(md)
