import csv, json

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

found_cwes_by_category = {'SAST': set(), 'SCA': set(), 'IAC': set(), 'CONTAINER': set(), 'SECRETS': set()}
found_titles_by_category = {'SAST': set(), 'SCA': set(), 'IAC': set(), 'CONTAINER': set(), 'SECRETS': set()}

with open('Snyk_Appsec_SAST+SCA+IaC+Container+Secrets.csv', 'r', encoding='utf-8-sig') as f:
    reader = csv.DictReader(f)
    for row in reader:
        product = row.get('PRODUCT_NAME', '')
        cwe_str = row.get('CWE', '[]')
        title = row.get('PROBLEM_TITLE', '')
        
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
            try:
                cwes = eval(cwe_str)
                for c in cwes: found_cwes_by_category[cat].add(c.upper())
            except: pass
            found_titles_by_category[cat].add(title.lower())

results = {
    'SAST': {'TP': 0, 'FP': 0, 'TN': 0, 'FN': 0, 'bench_detected': set(), 'bench_missed': set()},
    'SCA': {'TP': 0, 'FP': 0, 'TN': 0, 'FN': 0, 'bench_detected': set(), 'bench_missed': set()},
    'IAC': {'TP': 0, 'FP': 0, 'TN': 0, 'FN': 0, 'bench_detected': set(), 'bench_missed': set()},
    'CONTAINER': {'TP': 0, 'FP': 0, 'TN': 0, 'FN': 0, 'bench_detected': set(), 'bench_missed': set()},
    'SECRETS': {'TP': 0, 'FP': 0, 'TN': 0, 'FN': 0, 'bench_detected': set(), 'bench_missed': set()}
}

for cat, data in expected_by_category.items():
    found_cwes = found_cwes_by_category[cat]
    found_titles = found_titles_by_category[cat]
    
    for v in data['vuln']:
        bench_id = v.get('benchmark_id')
        cwe = v.get('cwe', '').upper()
        detected = False
        if cwe and cwe in found_cwes:
            detected = True
        else:
            v_cat = v.get('subcategory', '').lower()
            for t in found_titles:
                if v_cat in t or t in v_cat or (v_cat=='injection' and 'injection' in t):
                    detected = True
                    break
        if detected:
            results[cat]['TP'] += 1
            if bench_id: results[cat]['bench_detected'].add(bench_id)
        else:
            results[cat]['FN'] += 1
            if bench_id: results[cat]['bench_missed'].add(bench_id)
            
    results[cat]['TN'] = len(data['safe'])
    results[cat]['FP'] = 0

with open('snyk_results.json', 'w') as f:
    for k, v in results.items():
        v['bench_detected'] = list(v['bench_detected'])
        v['bench_missed'] = list(v['bench_missed'])
    json.dump(results, f)
