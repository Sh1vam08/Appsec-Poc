import csv, json

with open('benchmark-state/vulnerability_register.json', 'r', encoding='utf-8') as f:
    vuln_register = json.load(f).get('entries', [])

expected_sca = {'vuln': [], 'safe': []}

for vuln in vuln_register:
    cat = vuln.get('category', '').upper()
    if cat == 'SCA':
        if vuln.get('variant') == 'vulnerable':
            expected_sca['vuln'].append(vuln)
        elif vuln.get('variant') == 'safe':
            expected_sca['safe'].append(vuln)

findings = []
with open('Snyk_Appsec_SAST+SCA+IaC+Container+Secrets.csv', 'r', encoding='utf-8-sig') as f:
    reader = csv.DictReader(f)
    for row in reader:
        product = row.get('PRODUCT_NAME', '')
        if product == 'Snyk Open Source':
            cwe_str = row.get('CWE', '[]')
            title = row.get('PROBLEM_TITLE', '')
            proj = row.get('PROJECT_NAME', '')
            cwes = []
            try:
                cwes = eval(cwe_str)
                cwes = [c.upper() for c in cwes]
            except: pass
            findings.append({'cwes': cwes, 'title': title.lower(), 'original_title': title, 'project': proj})

r = {'TP': 0, 'FP': 0, 'TN': 0, 'FN': 0, 'bench_evidence': {}, 'bench_missed_evidence': {}, 'bench_missed': set()}

for v in expected_sca['vuln']:
    bench_id = v.get('benchmark_id')
    cwe = v.get('cwe', '').upper()
    v_cat = v.get('subcategory', '').lower()
    file_path = v.get('file', 'Unknown File')
    line_num = v.get('line', '')
    location = f"{file_path}:{line_num}" if line_num else file_path
    
    detected_evidence = []
    
    for f in findings:
        match = False
        if cwe and cwe in f['cwes']: match = True
        elif v_cat in f['title'] or f['title'] in v_cat or (v_cat=='injection' and 'injection' in f['title']): match = True
        
        if match:
            detected_evidence.append(f"Found: {f['original_title']} at {location}")
            
    if detected_evidence:
        r['TP'] += 1
        if bench_id: 
            r['bench_evidence'][bench_id] = list(set(detected_evidence))[:2]
    else:
        r['FN'] += 1
        if bench_id: 
            r['bench_missed'].add(bench_id)
            r['bench_missed_evidence'][bench_id] = f"Missed vulnerability at {location}"
        
r['TN'] = len(expected_sca['safe'])

with open('benchmark-state/excel_capability_mapping.json', 'r', encoding='utf-8') as f:
    caps = json.load(f).get('SCA Functional', {})

md = '# Snyk SCA Analysis Report\n\n'
md += 'This report evaluates Snyk strictly against the SCA capabilities.\n\n'

md += '## SCA Capability Checklist\n'

for cap_name, bench_ids in caps.items():
    num_total = len(bench_ids)
    detected_bids = [bid for bid in bench_ids if bid in r['bench_evidence']]
    missed_bids = [bid for bid in bench_ids if bid in r['bench_missed_evidence']]
    num_detected = len(detected_bids)
    
    if num_total == 0:
        status = 'Not Present'
        evidence = 'No test scenarios seeded for this capability.'
    elif num_detected == 0:
        status = 'Not Present'
        ev_list = []
        for bid in missed_bids: ev_list.append(r['bench_missed_evidence'][bid])
        evidence = ' \n  '.join(list(set(ev_list))[:3])
    elif num_detected == num_total:
        status = 'Present'
        ev_list = []
        for bid in detected_bids: ev_list.extend(r['bench_evidence'][bid])
        evidence = ' \n  '.join(list(set(ev_list))[:3])
    else:
        status = 'Present (Partially)'
        ev_list = []
        for bid in detected_bids: ev_list.extend(r['bench_evidence'][bid])
        evidence = ' \n  '.join(list(set(ev_list))[:3])
        
    md += f'- **{cap_name}**: {status} \n  *Evidence: {evidence}*\n'

with open('C:/Users/ABCD/.gemini/antigravity-ide/brain/7db8bd5b-13ff-4134-aaa7-b564d9f5fb33/Snyk_SCA_Analysis.md', 'w', encoding='utf-8') as f:
    f.write(md)
