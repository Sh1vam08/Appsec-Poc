import csv, json
import pandas as pd
import re

with open('benchmark-state/vulnerability_register.json', 'r', encoding='utf-8') as f:
    vuln_register = json.load(f).get('entries', [])

expected_by_category = {
    'SAST': {'vuln': [], 'safe': []},
    'SCA': {'vuln': [], 'safe': []},
    'IAC': {'vuln': [], 'safe': []},
    'CONTAINER': {'vuln': [], 'safe': []},
    'SECRETS': {'vuln': [], 'safe': []}
}

for vuln in vuln_register:
    cat = vuln.get('category', '').upper()
    if cat == 'DAST': continue
    if cat == 'SECRET': cat = 'SECRETS'
    elif cat == 'CONT': cat = 'CONTAINER'
    
    if cat in expected_by_category:
        if vuln.get('variant') == 'vulnerable':
            expected_by_category[cat]['vuln'].append(vuln)
        elif vuln.get('variant') == 'safe':
            expected_by_category[cat]['safe'].append(vuln)

# We map CWEs and Titles from Snyk to specific evidence strings
snyk_findings_by_category = {
    'SAST': [], 'SCA': [], 'IAC': [], 'CONTAINER': [], 'SECRETS': []
}

with open('Snyk_Appsec_SAST+SCA+IaC+Container+Secrets.csv', 'r', encoding='utf-8-sig') as f:
    reader = csv.DictReader(f)
    for row in reader:
        product = row.get('PRODUCT_NAME', '')
        cwe_str = row.get('CWE', '[]')
        title = row.get('PROBLEM_TITLE', '')
        proj = row.get('PROJECT_NAME', '')
        
        cat = None
        if product == 'Snyk Code':
            if any(x in title for x in ['Secret', 'Hardcoded', 'Credential', 'Password', 'Key', 'Token']):
                cat = 'SECRETS'
            else:
                cat = 'SAST'
        elif product == 'Snyk Open Source': cat = 'SCA'
        elif product == 'Snyk IaC': cat = 'IAC'
        elif product == 'Snyk Container': cat = 'CONTAINER'
        
        if cat:
            cwes = []
            try:
                cwes = eval(cwe_str)
                cwes = [c.upper() for c in cwes]
            except: pass
            
            snyk_findings_by_category[cat].append({
                'cwes': cwes,
                'title': title.lower(),
                'original_title': title,
                'project': proj
            })

results = {
    'SAST': {'TP': 0, 'FP': 0, 'TN': 0, 'FN': 0, 'bench_evidence': {}, 'bench_missed': set()},
    'SCA': {'TP': 0, 'FP': 0, 'TN': 0, 'FN': 0, 'bench_evidence': {}, 'bench_missed': set()},
    'IAC': {'TP': 0, 'FP': 0, 'TN': 0, 'FN': 0, 'bench_evidence': {}, 'bench_missed': set()},
    'CONTAINER': {'TP': 0, 'FP': 0, 'TN': 0, 'FN': 0, 'bench_evidence': {}, 'bench_missed': set()},
    'SECRETS': {'TP': 0, 'FP': 0, 'TN': 0, 'FN': 0, 'bench_evidence': {}, 'bench_missed': set()}
}

for cat, data in expected_by_category.items():
    findings = snyk_findings_by_category[cat]
    
    for v in data['vuln']:
        bench_id = v.get('benchmark_id')
        cwe = v.get('cwe', '').upper()
        v_cat = v.get('subcategory', '').lower()
        
        detected_evidence = []
        
        for f in findings:
            match = False
            if cwe and cwe in f['cwes']: match = True
            elif v_cat in f['title'] or f['title'] in v_cat or (v_cat=='injection' and 'injection' in f['title']): match = True
            
            if match:
                detected_evidence.append(f"{f['original_title']} in {f['project']}")
                
        if detected_evidence:
            results[cat]['TP'] += 1
            if bench_id: 
                results[cat]['bench_evidence'][bench_id] = list(set(detected_evidence))[:3] # store up to 3 pieces of evidence to avoid huge cells
        else:
            results[cat]['FN'] += 1
            if bench_id: results[cat]['bench_missed'].add(bench_id)
            
    results[cat]['TN'] = len(data['safe'])
    results[cat]['FP'] = 0

with open('benchmark-state/excel_capability_mapping.json', 'r', encoding='utf-8') as f:
    caps = json.load(f)

map_cat = {
    'SAST': 'SAST Functional',
    'SCA': 'SCA Functional',
    'IAC': 'IaC Functional',
    'CONTAINER': 'Container Functional',
    'SECRETS': 'Secrets Functional'
}

sheet_name_map = {
    'SAST': 'SAST Functional',
    'SCA': 'SCA Functional',
    'IAC': 'IaC Functional',
    'CONTAINER': 'Container Functional',
    'SECRETS': 'Secrets Functional'
}

# Create Excel writer
with pd.ExcelWriter('Snyk_Evaluation_Report.xlsx', engine='openpyxl') as writer:
    for cat, r in results.items():
        tp = r['TP']
        fn = r['FN']
        fp = r['FP']
        tn = r['TN']
        
        total_seeded = tp + fn
        total_findings = tp + fp
        
        detection_coverage = f"{(tp / total_seeded * 100):.1f}%" if total_seeded > 0 else "0.0%"
        accuracy = f"{(tp / total_findings * 100):.1f}%" if total_findings > 0 else "0.0%"
        miss_rate = f"{(fn / total_seeded * 100):.1f}%" if total_seeded > 0 else "0.0%"
        
        cat_key = map_cat.get(cat)
        sheet_data = []
        
        if cat_key and cat_key in caps:
            cap_dict = caps[cat_key]
            for cap_name, bench_ids in cap_dict.items():
                num_total = len(bench_ids)
                detected_bids = [bid for bid in bench_ids if bid in r['bench_evidence']]
                num_detected = len(detected_bids)
                
                if num_total == 0 or num_detected == 0:
                    status = 'Not Avaialabe'
                    evidence = 'No vulnerabilities detected for this capability.' if num_total > 0 else 'No test scenarios seeded.'
                elif num_detected == num_total:
                    status = 'Available'
                    ev_list = []
                    for bid in detected_bids: ev_list.extend(r['bench_evidence'][bid])
                    evidence = ' \n'.join(list(set(ev_list))[:5])
                else:
                    status = 'Partially Available'
                    ev_list = []
                    for bid in detected_bids: ev_list.extend(r['bench_evidence'][bid])
                    evidence = ' \n'.join(list(set(ev_list))[:5])
                    
                sheet_data.append({
                    'Capability': cap_name,
                    'Description': cap_name, # Since description isn't available easily, repeating capability name
                    'Availability with the Partners': status,
                    'Evidence': evidence
                })
        
        df = pd.DataFrame(sheet_data)
        
        # Append KPIs as empty rows then KPI data
        kpi_data = [
            {'Capability': '', 'Description': '', 'Availability with the Partners': '', 'Evidence': ''},
            {'Capability': 'KPI Metrices', 'Description': '', 'Availability with the Partners': '', 'Evidence': ''},
            {'Capability': 'Metric', 'Description': 'Value', 'Availability with the Partners': '', 'Evidence': ''},
            {'Capability': 'Detection Coverage', 'Description': detection_coverage, 'Availability with the Partners': '', 'Evidence': ''},
            {'Capability': 'Accuracy', 'Description': accuracy, 'Availability with the Partners': '', 'Evidence': ''},
            {'Capability': 'False Negatives', 'Description': miss_rate, 'Availability with the Partners': '', 'Evidence': ''},
            {'Capability': 'Scan Time', 'Description': 'N/A', 'Availability with the Partners': '', 'Evidence': ''},
            {'Capability': 'Cost', 'Description': 'N/A', 'Availability with the Partners': '', 'Evidence': ''}
        ]
        
        if cat == 'SAST':
            kpi_data.extend([
                {'Capability': 'Language Coverage', 'Description': 'N/A', 'Availability with the Partners': '', 'Evidence': ''},
                {'Capability': 'Reachability Analysis Accuracy', 'Description': 'N/A', 'Availability with the Partners': '', 'Evidence': ''},
                {'Capability': 'Remediation Guidance Efficacy', 'Description': 'N/A', 'Availability with the Partners': '', 'Evidence': ''}
            ])
        elif cat == 'SCA':
            kpi_data.extend([
                {'Capability': 'Language Coverage', 'Description': 'N/A', 'Availability with the Partners': '', 'Evidence': ''},
                {'Capability': 'Exploitability Context Accuracy', 'Description': 'N/A', 'Availability with the Partners': '', 'Evidence': ''},
                {'Capability': 'Transitive Dependency Accuracy', 'Description': 'N/A', 'Availability with the Partners': '', 'Evidence': ''}
            ])
        elif cat == 'CONTAINER':
            kpi_data.extend([
                {'Capability': 'Layer Coverage', 'Description': 'N/A', 'Availability with the Partners': '', 'Evidence': ''},
                {'Capability': 'Base Image Accuracy', 'Description': 'N/A', 'Availability with the Partners': '', 'Evidence': ''}
            ])
            
        df = pd.concat([df, pd.DataFrame(kpi_data)], ignore_index=True)
        
        # Write to sheet
        sheet_name = sheet_name_map.get(cat)
        df.to_excel(writer, sheet_name=sheet_name, index=False)
