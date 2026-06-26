# KPI Framework Documentation

## Enterprise AppSec Benchmark Suite v1.0.0

### Overview

The KPI Framework is the scoring and evaluation engine for the Enterprise AppSec Benchmark Suite. It ingests vendor scan results, compares them against the 210-scenario ground truth, and produces comprehensive metrics, grades, and reports for vendor comparison.

---

## Architecture

```
┌───────────────────┐     ┌──────────────────────┐     ┌──────────────────┐
│  Vendor Scan      │     │   Ground Truth        │     │  Scoring Rubric  │
│  Results          │     │  (expected_findings)  │     │  (weights,       │
│  (SARIF/JSON/CSV) │     │  (vuln_register)      │     │   thresholds)    │
└────────┬──────────┘     └──────────┬────────────┘     └────────┬─────────┘
         │                           │                            │
         └───────────┐  ┌────────────┘  ┌─────────────────────────┘
                     ▼  ▼              ▼
              ┌──────────────────────────────┐
              │       KPI Calculator          │
              │  (scripts/kpi_calculator.py)  │
              └──────────────┬───────────────┘
                             │
              ┌──────────────┼──────────────────┐
              ▼              ▼                  ▼
     ┌────────────┐  ┌──────────────┐  ┌────────────────┐
     │ JSON Report│  │ MD Report    │  │ Dashboard Data │
     │            │  │              │  │ (6 JSON feeds) │
     └────────────┘  └──────────────┘  └────────────────┘
```

---

## Core Metrics

### 1. Confusion Matrix

Every benchmark scenario is classified into one of four outcomes:

| | Scanner Reports Finding | Scanner Reports No Finding |
|---|---|---|
| **Actually Vulnerable** | ✅ True Positive (TP) | ❌ False Negative (FN) |
| **Actually Safe** | ❌ False Positive (FP) | ✅ True Negative (TN) |

### 2. Primary KPIs

| KPI | Formula | Description |
|-----|---------|-------------|
| **Precision** | TP / (TP + FP) | Of all findings reported, how many are real? |
| **Recall (Detection Coverage)** | TP / (TP + FN) | Of all real vulnerabilities, how many were found? |
| **Accuracy** | (TP + TN) / Total | Overall correctness across all scenarios |
| **F1 Score** | 2 × (P × R) / (P + R) | Harmonic mean of precision and recall |
| **False Positive Rate** | FP / (FP + TN) | How often safe code is flagged as vulnerable |
| **False Negative Rate** | FN / (FN + TP) | How often real vulnerabilities are missed |
| **Severity Accuracy** | Correct Severities / Total Detected | How accurately severity is classified |

### 3. Composite Score (0-100)

The composite score combines all metrics using the weighted rubric:

| Component | Weight | Composition |
|-----------|--------|-------------|
| Core Detection | 60% | F1 (40%) + Recall (30%) + Precision (20%) + (1-FPR) (10%) |
| Severity Accuracy | 15% | Correct severity classifications |
| Coverage Breadth | 15% | Proportion of categories covered (SAST, DAST, SCA, etc.) |
| AI Capabilities | 10% | AI feature evaluation scores |

### 4. Letter Grades

| Grade | Score Range | Meaning |
|-------|-----------|---------|
| A+ | ≥ 95 | Exceptional - Best-in-class |
| A | ≥ 90 | Excellent - Comprehensive detection |
| A- | ≥ 85 | Very Good - Minor gaps |
| B+ | ≥ 80 | Good - Solid but with patterns |
| B | ≥ 75 | Above Average - Core detection works |
| B- | ≥ 70 | Adequate - Room for improvement |
| C+ | ≥ 65 | Below Average - Notable issues |
| C | ≥ 60 | Poor - Significant gaps |
| D | ≥ 50 | Very Poor - Major deficiencies |
| F | < 50 | Failing - Not production-ready |

---

## Category Breakdown

KPIs are computed at multiple granularity levels:

### Per-Category
- **SAST** (80 scenarios): SQL Injection, XSS, SSRF, Command Injection, XXE, etc.
- **DAST** (20 scenarios): Runtime vulnerability detection
- **SCA** (40 scenarios): Vulnerable dependencies, reachability
- **SECRET** (30 scenarios): Credential and API key detection
- **CONTAINER** (20 scenarios): Dockerfile misconfigurations
- **IAC** (20 scenarios): Terraform, Kubernetes, Helm misconfigs
- **CI/CD** (10 scenarios): Pipeline security misconfigurations

### Per-CWE
Individual CWE performance (e.g., CWE-89 SQL Injection, CWE-79 XSS)

### Per-Severity
Performance breakdown by expected severity level (CRITICAL, HIGH, MEDIUM, LOW)

---

## AI Capability Evaluation

Six AI capabilities are evaluated when applicable:

| Capability | Weight | What It Measures |
|-----------|--------|-----------------|
| Fix Generation | 25% | Can the tool generate correct code fixes? |
| Remediation Guidance | 20% | Does it provide actionable remediation steps? |
| Root Cause Analysis | 20% | Can it identify the underlying vulnerability cause? |
| Reachability Analysis | 15% | Can it determine if a vulnerability is reachable? |
| Prioritization | 10% | Does it correctly prioritize findings? |
| Risk Ranking | 10% | Does it accurately rank risk levels? |

---

## Usage

### Running the KPI Calculator

```bash
# Demo mode (synthetic data)
python scripts/kpi_calculator.py --demo

# With real scan results (SARIF format)
python scripts/kpi_calculator.py \
  --scan-results path/to/results.sarif \
  --format sarif \
  --vendor "Vendor A"

# With JSON results
python scripts/kpi_calculator.py \
  --scan-results path/to/results.json \
  --format json \
  --vendor "Vendor B"

# With CSV results
python scripts/kpi_calculator.py \
  --scan-results path/to/results.csv \
  --format csv \
  --vendor "Vendor C" \
  --output-dir ./reports
```

### Input Formats

#### SARIF 2.1.0
Standard SARIF output from any compliant scanner. The calculator extracts benchmark IDs from:
1. `result.properties.benchmark_id` (preferred)
2. File path inference from `result.locations[].physicalLocation.artifactLocation.uri`

#### JSON
Simple JSON array:
```json
[
  {
    "benchmark_id": "BENCH-SAST-001",
    "cwe": "CWE-89",
    "severity": "HIGH",
    "detected": true
  }
]
```

#### CSV
```csv
benchmark_id,cwe,severity,detected
BENCH-SAST-001,CWE-89,HIGH,true
BENCH-SAST-002,CWE-89,NONE,false
```

### Output Reports

The calculator generates three output types:

1. **JSON Report** (`reports/kpi_report_<vendor>.json`) - Full machine-readable KPI data
2. **Markdown Report** (`reports/kpi_report_<vendor>.md`) - Human-readable report
3. **Dashboard Data** (`reports/dashboard-data/`) - Six JSON feeds for dashboard rendering:
   - `summary_card.json` - Headline KPIs
   - `radar_chart.json` - Category F1 radar
   - `confusion_heatmap.json` - TP/TN/FP/FN matrix
   - `category_bars.json` - Per-category grouped bars
   - `ai_capability_spider.json` - AI feature scores
   - `cwe_treemap.json` - Per-CWE performance

---

## Multi-Vendor Comparison

The `VendorComparator` class enables side-by-side vendor evaluation:

```python
from kpi_calculator import KPICalculator, VendorComparator

comparator = VendorComparator()

# Add multiple vendor results
comparator.add_vendor("Vendor A", results_a)
comparator.add_vendor("Vendor B", results_b)
comparator.add_vendor("Vendor C", results_c)

# Generate comparison
comparison = comparator.generate_comparison()
comparator.generate_comparison_report(Path("reports/comparison.md"))
```

---

## Scoring Rubric

The scoring rubric (`benchmark-state/scoring_rubric.json`) is fully configurable:

### Category Weights
| Category | Weight | Rationale |
|----------|--------|-----------|
| SAST | 30% | Largest scenario pool, critical for shift-left |
| SCA | 20% | Supply chain security importance |
| DAST | 15% | Runtime detection validation |
| SECRET | 10% | Credential leak prevention |
| CONTAINER | 10% | Container hardening |
| IAC | 10% | Infrastructure misconfiguration |
| CI/CD | 5% | Pipeline security (newest category) |

### Penalty Rules
- **Critical Miss**: -0.5 per missed HIGH/CRITICAL vulnerability (max -10)
- **Excessive FP**: -0.3 per % above 20% FPR threshold (max -5)
- **Category Zero**: -3.0 per category with zero score (max -15)

### Minimum Viable Thresholds
A vendor is considered **production-ready** only if meeting:
- Precision ≥ 60%
- Recall ≥ 50%
- F1 Score ≥ 55%
- FPR ≤ 30%
- ≥ 4 categories covered

---

## File Reference

| File | Purpose |
|------|---------|
| `scripts/kpi_calculator.py` | Main KPI computation engine |
| `benchmark-state/scoring_rubric.json` | Weights, thresholds, and grading criteria |
| `benchmark-state/report_templates.json` | Report section definitions and visualizations |
| `benchmark-state/dashboard_data_schema.json` | Dashboard feed schemas and rendering metadata |
| `benchmark-state/expected_findings.json` | Ground truth for all 210 scenarios |
| `benchmark-state/vulnerability_register.json` | Vulnerability metadata registry |
| `benchmark-state/capability_mapping.json` | Capability-to-benchmark mappings |

---

## Extending the Framework

### Adding New Metrics
1. Add computation logic to `KPICalculator.compute()`
2. Update `scoring_rubric.json` weights if the metric affects scoring
3. Add report section to `report_templates.json`
4. Update dashboard schema in `dashboard_data_schema.json`

### Adding New Categories
1. Add the category prefix to `CATEGORY_PREFIXES` in `kpi_calculator.py`
2. Add the category to `CATEGORIES` list
3. Update `category_weights` in `scoring_rubric.json`
4. Add expected findings to `expected_findings.json`

### Custom Report Formats
Implement additional methods in `ReportGenerator` class following the pattern of `generate_markdown_report()`.
