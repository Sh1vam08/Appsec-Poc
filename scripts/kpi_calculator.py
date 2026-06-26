#!/usr/bin/env python3
"""
Enterprise AppSec Benchmark Suite - KPI Calculator
===================================================
Ingests vendor scan results (SARIF, JSON, CSV) and compares against
the expected_findings.json ground truth to produce comprehensive KPIs.

Usage:
    python kpi_calculator.py --scan-results <path> --format <sarif|json|csv>
    python kpi_calculator.py --scan-results <path> --format sarif --vendor "Vendor A"
    python kpi_calculator.py --demo  (runs with synthetic data for validation)
"""

import json
import os
import sys
import csv
import argparse
import copy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BENCHMARK_STATE_DIR = Path(__file__).resolve().parent.parent / "benchmark-state"
EXPECTED_FINDINGS_FILE = BENCHMARK_STATE_DIR / "expected_findings.json"
VULNERABILITY_REGISTER_FILE = BENCHMARK_STATE_DIR / "vulnerability_register.json"
CAPABILITY_MAPPING_FILE = BENCHMARK_STATE_DIR / "capability_mapping.json"
SCORING_RUBRIC_FILE = BENCHMARK_STATE_DIR / "scoring_rubric.json"
REPORT_OUTPUT_DIR = Path(__file__).resolve().parent.parent / "reports"
DASHBOARD_OUTPUT_DIR = REPORT_OUTPUT_DIR / "dashboard-data"

CATEGORIES = ["SAST", "DAST", "SCA", "SECRET", "CONTAINER", "IAC", "CICD"]

CATEGORY_PREFIXES = {
    "SAST": "BENCH-SAST-",
    "DAST": "BENCH-DAST-",
    "SCA": "BENCH-SCA-",
    "SECRET": "BENCH-SECRET-",
    "CONTAINER": "BENCH-CONTAINER-",
    "IAC": "BENCH-IAC-",
    "CICD": "BENCH-CICD-",
}


# ---------------------------------------------------------------------------
# Data Loading
# ---------------------------------------------------------------------------
def load_json(path: Path) -> dict:
    """Load and return a JSON file."""
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_expected_findings() -> list[dict]:
    """Load the expected findings ground truth."""
    data = load_json(EXPECTED_FINDINGS_FILE)
    return data.get("findings", [])


def load_vulnerability_register() -> list[dict]:
    """Load the vulnerability register."""
    data = load_json(VULNERABILITY_REGISTER_FILE)
    return data.get("entries", [])


def load_capability_mapping() -> list[dict]:
    """Load the capability mapping."""
    data = load_json(CAPABILITY_MAPPING_FILE)
    return data.get("capabilities", [])


def load_scoring_rubric() -> dict:
    """Load the scoring rubric with weights and thresholds."""
    return load_json(SCORING_RUBRIC_FILE)


# ---------------------------------------------------------------------------
# Scan Result Parsers
# ---------------------------------------------------------------------------
def parse_sarif(file_path: str) -> list[dict]:
    """
    Parse SARIF 2.1.0 scan results into normalized finding records.
    Each record: { benchmark_id, detected_cwe, detected_severity, detected }
    """
    data = load_json(Path(file_path))
    findings = []

    for run in data.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            level = result.get("level", "warning")
            message = result.get("message", {}).get("text", "")

            # Extract benchmark_id from properties, tags, or message
            benchmark_id = None
            properties = result.get("properties", {})
            if "benchmark_id" in properties:
                benchmark_id = properties["benchmark_id"]
            else:
                # Try to extract from file path in locations
                for location in result.get("locations", []):
                    phys = location.get("physicalLocation", {})
                    artifact = phys.get("artifactLocation", {})
                    uri = artifact.get("uri", "")
                    benchmark_id = _infer_benchmark_id_from_path(uri)
                    if benchmark_id:
                        break

            if not benchmark_id:
                continue

            severity_map = {
                "error": "HIGH",
                "warning": "MEDIUM",
                "note": "LOW",
                "none": "INFORMATIONAL",
            }

            findings.append({
                "benchmark_id": benchmark_id,
                "detected_cwe": _extract_cwe(rule_id, properties),
                "detected_severity": severity_map.get(level, "MEDIUM"),
                "detected": True,
                "rule_id": rule_id,
                "message": message,
            })

    return findings


def parse_json_results(file_path: str) -> list[dict]:
    """
    Parse a simple JSON array of scan results.
    Expected format: [{ benchmark_id, cwe, severity, detected, ... }, ...]
    """
    data = load_json(Path(file_path))
    results = data if isinstance(data, list) else data.get("results", [])

    findings = []
    for item in results:
        findings.append({
            "benchmark_id": item.get("benchmark_id", ""),
            "detected_cwe": item.get("cwe", item.get("detected_cwe", "")),
            "detected_severity": item.get("severity", item.get("detected_severity", "MEDIUM")),
            "detected": item.get("detected", True),
            "rule_id": item.get("rule_id", ""),
            "message": item.get("message", ""),
        })

    return findings


def parse_csv_results(file_path: str) -> list[dict]:
    """
    Parse CSV scan results.
    Expected columns: benchmark_id, cwe, severity, detected
    """
    findings = []
    with open(file_path, "r", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            findings.append({
                "benchmark_id": row.get("benchmark_id", ""),
                "detected_cwe": row.get("cwe", row.get("detected_cwe", "")),
                "detected_severity": row.get("severity", row.get("detected_severity", "MEDIUM")),
                "detected": row.get("detected", "true").lower() in ("true", "1", "yes"),
                "rule_id": row.get("rule_id", ""),
                "message": row.get("message", ""),
            })

    return findings


PARSERS = {
    "sarif": parse_sarif,
    "json": parse_json_results,
    "csv": parse_csv_results,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _extract_cwe(rule_id: str, properties: dict) -> str:
    """Extract CWE from rule ID or properties."""
    if "cwe" in properties:
        return properties["cwe"]
    # Try common patterns like "CWE-89", "java/sql-injection"
    if rule_id.upper().startswith("CWE-"):
        return rule_id.upper()
    return ""


def _infer_benchmark_id_from_path(file_path: str) -> str | None:
    """Attempt to infer benchmark_id from file path (heuristic)."""
    # This is a fallback - ideally scan results include benchmark_id directly
    return None


def _safe_div(numerator: float, denominator: float) -> float:
    """Division with zero guard."""
    return round(numerator / denominator, 6) if denominator > 0 else 0.0


def _classify_category(benchmark_id: str) -> str:
    """Determine the category from benchmark_id prefix."""
    for cat, prefix in CATEGORY_PREFIXES.items():
        if benchmark_id.startswith(prefix):
            return cat
    return "UNKNOWN"


# ---------------------------------------------------------------------------
# Core KPI Computation
# ---------------------------------------------------------------------------
class KPICalculator:
    """
    Compares scan results against expected findings to produce KPIs.
    """

    def __init__(
        self,
        expected_findings: list[dict],
        vulnerability_register: list[dict],
        capability_mapping: list[dict],
        scoring_rubric: dict,
    ):
        self.expected = {f["benchmark_id"]: f for f in expected_findings}
        self.vuln_register = {e["benchmark_id"]: e for e in vulnerability_register}
        self.capabilities = capability_mapping
        self.rubric = scoring_rubric

        # Build capability lookup by benchmark_id
        self.cap_by_benchmark = {}
        for cap in self.capabilities:
            for bid in cap.get("benchmark_ids", []):
                self.cap_by_benchmark[bid] = cap

    def compute(self, scan_results: list[dict], vendor_name: str = "Unknown") -> dict:
        """
        Main computation entry point.
        Returns a comprehensive KPI report dictionary.
        """
        scan_lookup = {}
        for sr in scan_results:
            bid = sr.get("benchmark_id")
            if bid:
                scan_lookup[bid] = sr

        # --- Confusion Matrix ---
        tp = 0  # True Positive:  expected TP, scanner detected
        tn = 0  # True Negative:  expected TN (safe), scanner did NOT detect
        fp = 0  # False Positive: expected TN (safe), scanner DID detect
        fn = 0  # False Negative: expected TP, scanner did NOT detect

        # Per-category confusion matrices
        cat_matrices = {cat: {"tp": 0, "tn": 0, "fp": 0, "fn": 0} for cat in CATEGORIES}

        # Per-CWE confusion matrices
        cwe_matrices: dict[str, dict[str, int]] = {}

        # Per-severity confusion matrices
        sev_matrices: dict[str, dict[str, int]] = {}

        # Severity accuracy tracking
        severity_correct = 0
        severity_total = 0

        # Reachability accuracy tracking
        reachability_correct = 0
        reachability_total = 0

        # AI capability tracking
        ai_metrics = {
            "fix_generation": {"applicable": 0, "correct": 0},
            "remediation_guidance": {"applicable": 0, "correct": 0},
            "root_cause_analysis": {"applicable": 0, "correct": 0},
            "reachability_analysis": {"applicable": 0, "correct": 0},
            "prioritization": {"applicable": 0, "correct": 0},
            "risk_ranking": {"applicable": 0, "correct": 0},
        }

        # Detailed per-benchmark results
        benchmark_results = []

        for bid, expected in self.expected.items():
            category = _classify_category(bid)
            cwe = expected.get("expected_cwe", "UNKNOWN")
            severity = expected.get("expected_severity", "UNKNOWN")
            expected_detection = expected.get("expected_detection", "TRUE_POSITIVE")

            # Ensure CWE and severity matrices exist
            if cwe not in cwe_matrices:
                cwe_matrices[cwe] = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
            if severity not in sev_matrices:
                sev_matrices[severity] = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}

            scan_hit = scan_lookup.get(bid)
            detected = scan_hit is not None and scan_hit.get("detected", False)

            is_expected_positive = expected_detection in ("TRUE_POSITIVE",)
            is_expected_negative = expected_detection in ("TRUE_NEGATIVE",)

            result_entry = {
                "benchmark_id": bid,
                "category": category,
                "cwe": cwe,
                "expected_detection": expected_detection,
                "actual_detected": detected,
                "classification": "",
                "severity_match": None,
                "cwe_match": None,
            }

            if is_expected_positive and detected:
                tp += 1
                cat_matrices.get(category, cat_matrices.get("SAST", {}))["tp"] = \
                    cat_matrices.get(category, {"tp": 0})["tp"] + 1
                cwe_matrices[cwe]["tp"] += 1
                sev_matrices[severity]["tp"] += 1
                result_entry["classification"] = "TRUE_POSITIVE"
            elif is_expected_positive and not detected:
                fn += 1
                cat_matrices.get(category, cat_matrices.get("SAST", {}))["fn"] = \
                    cat_matrices.get(category, {"fn": 0})["fn"] + 1
                cwe_matrices[cwe]["fn"] += 1
                sev_matrices[severity]["fn"] += 1
                result_entry["classification"] = "FALSE_NEGATIVE"
            elif is_expected_negative and not detected:
                tn += 1
                cat_matrices.get(category, cat_matrices.get("SAST", {}))["tn"] = \
                    cat_matrices.get(category, {"tn": 0})["tn"] + 1
                cwe_matrices[cwe]["tn"] += 1
                sev_matrices[severity]["tn"] += 1
                result_entry["classification"] = "TRUE_NEGATIVE"
            elif is_expected_negative and detected:
                fp += 1
                cat_matrices.get(category, cat_matrices.get("SAST", {}))["fp"] = \
                    cat_matrices.get(category, {"fp": 0})["fp"] + 1
                cwe_matrices[cwe]["fp"] += 1
                sev_matrices[severity]["fp"] += 1
                result_entry["classification"] = "FALSE_POSITIVE"

            # Severity accuracy (only for detected findings)
            if detected and scan_hit:
                severity_total += 1
                detected_sev = scan_hit.get("detected_severity", "")
                expected_sev = expected.get("expected_severity", "")
                if detected_sev == expected_sev:
                    severity_correct += 1
                    result_entry["severity_match"] = True
                else:
                    result_entry["severity_match"] = False

                # CWE match check
                detected_cwe = scan_hit.get("detected_cwe", "")
                if detected_cwe == cwe:
                    result_entry["cwe_match"] = True
                else:
                    result_entry["cwe_match"] = False

            # AI capability metrics (count applicable, assume detected = evaluated correctly for demo)
            ai_eval = expected.get("ai_evaluation", {})
            for ai_key, metric_key in [
                ("fix_generation_applicable", "fix_generation"),
                ("remediation_guidance_applicable", "remediation_guidance"),
                ("root_cause_analysis_applicable", "root_cause_analysis"),
                ("reachability_analysis_applicable", "reachability_analysis"),
                ("prioritization_applicable", "prioritization"),
                ("risk_ranking_applicable", "risk_ranking"),
            ]:
                if ai_eval.get(ai_key, False):
                    ai_metrics[metric_key]["applicable"] += 1
                    # In a real evaluation, we'd check the scan result's AI outputs
                    # For now, TP detections with AI capabilities count as correct
                    if detected and is_expected_positive:
                        ai_metrics[metric_key]["correct"] += 1

            benchmark_results.append(result_entry)

        # --- Compute Primary KPIs ---
        total = tp + tn + fp + fn
        precision = _safe_div(tp, tp + fp)
        recall = _safe_div(tp, tp + fn)
        accuracy = _safe_div(tp + tn, total)
        f1_score = _safe_div(2 * precision * recall, precision + recall)
        false_positive_rate = _safe_div(fp, fp + tn)
        false_negative_rate = _safe_div(fn, fn + tp)
        detection_coverage = _safe_div(tp, tp + fn)  # Same as recall
        severity_accuracy = _safe_div(severity_correct, severity_total)

        # --- Per-Category KPIs ---
        category_kpis = {}
        for cat in CATEGORIES:
            m = cat_matrices.get(cat, {"tp": 0, "tn": 0, "fp": 0, "fn": 0})
            cat_total = m["tp"] + m["tn"] + m["fp"] + m["fn"]
            if cat_total > 0:
                category_kpis[cat] = {
                    "total_benchmarks": cat_total,
                    "true_positives": m["tp"],
                    "true_negatives": m["tn"],
                    "false_positives": m["fp"],
                    "false_negatives": m["fn"],
                    "precision": _safe_div(m["tp"], m["tp"] + m["fp"]),
                    "recall": _safe_div(m["tp"], m["tp"] + m["fn"]),
                    "accuracy": _safe_div(m["tp"] + m["tn"], cat_total),
                    "f1_score": _safe_div(
                        2 * _safe_div(m["tp"], m["tp"] + m["fp"]) * _safe_div(m["tp"], m["tp"] + m["fn"]),
                        _safe_div(m["tp"], m["tp"] + m["fp"]) + _safe_div(m["tp"], m["tp"] + m["fn"]),
                    ),
                    "false_positive_rate": _safe_div(m["fp"], m["fp"] + m["tn"]),
                }

        # --- Per-CWE KPIs ---
        cwe_kpis = {}
        for cwe, m in cwe_matrices.items():
            cwe_total = m["tp"] + m["tn"] + m["fp"] + m["fn"]
            if cwe_total > 0:
                cwe_kpis[cwe] = {
                    "total_benchmarks": cwe_total,
                    "precision": _safe_div(m["tp"], m["tp"] + m["fp"]),
                    "recall": _safe_div(m["tp"], m["tp"] + m["fn"]),
                    "f1_score": _safe_div(
                        2 * _safe_div(m["tp"], m["tp"] + m["fp"]) * _safe_div(m["tp"], m["tp"] + m["fn"]),
                        _safe_div(m["tp"], m["tp"] + m["fp"]) + _safe_div(m["tp"], m["tp"] + m["fn"]),
                    ),
                }

        # --- AI Capability Scores ---
        ai_scores = {}
        for key, metric in ai_metrics.items():
            ai_scores[key] = {
                "applicable_count": metric["applicable"],
                "correct_count": metric["correct"],
                "score": _safe_div(metric["correct"], metric["applicable"]),
            }

        # --- Weighted Composite Score ---
        composite_score = self._compute_composite_score(
            precision, recall, accuracy, f1_score,
            false_positive_rate, severity_accuracy,
            category_kpis, ai_scores
        )

        # --- Grade ---
        grade = self._compute_grade(composite_score)

        return {
            "report_metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "vendor_name": vendor_name,
                "benchmark_version": "1.0.0",
                "total_benchmarks_evaluated": total,
                "scan_results_count": len(scan_results),
                "calculator_version": "1.0.0",
            },
            "summary": {
                "composite_score": composite_score,
                "grade": grade,
                "precision": precision,
                "recall": recall,
                "accuracy": accuracy,
                "f1_score": f1_score,
                "detection_coverage": detection_coverage,
                "false_positive_rate": false_positive_rate,
                "false_negative_rate": false_negative_rate,
                "severity_accuracy": severity_accuracy,
            },
            "confusion_matrix": {
                "true_positives": tp,
                "true_negatives": tn,
                "false_positives": fp,
                "false_negatives": fn,
                "total": total,
            },
            "category_breakdown": category_kpis,
            "cwe_breakdown": cwe_kpis,
            "ai_capability_scores": ai_scores,
            "benchmark_results": benchmark_results,
        }

    def _compute_composite_score(
        self,
        precision: float,
        recall: float,
        accuracy: float,
        f1_score: float,
        fpr: float,
        severity_accuracy: float,
        category_kpis: dict,
        ai_scores: dict,
    ) -> float:
        """
        Compute a weighted composite score (0-100) using the scoring rubric.
        """
        weights = self.rubric.get("weights", {})

        # Core detection metrics (60% default)
        core_weight = weights.get("core_detection", 0.60)
        core_score = (
            f1_score * 0.40 +
            recall * 0.30 +
            precision * 0.20 +
            (1.0 - fpr) * 0.10
        )

        # Severity & prioritization accuracy (15% default)
        sev_weight = weights.get("severity_accuracy", 0.15)
        sev_score = severity_accuracy

        # Coverage breadth (15% default)
        breadth_weight = weights.get("coverage_breadth", 0.15)
        cats_with_data = sum(1 for c in category_kpis if category_kpis[c]["total_benchmarks"] > 0)
        total_cats = len(CATEGORIES)
        breadth_score = _safe_div(cats_with_data, total_cats)

        # AI capabilities (10% default)
        ai_weight = weights.get("ai_capabilities", 0.10)
        ai_applicable = [s for s in ai_scores.values() if s["applicable_count"] > 0]
        ai_score = (
            sum(s["score"] for s in ai_applicable) / len(ai_applicable)
            if ai_applicable else 0.0
        )

        composite = (
            core_score * core_weight +
            sev_score * sev_weight +
            breadth_score * breadth_weight +
            ai_score * ai_weight
        ) * 100

        return round(min(100.0, max(0.0, composite)), 2)

    def _compute_grade(self, score: float) -> str:
        """Map composite score to a letter grade."""
        thresholds = self.rubric.get("grade_thresholds", {})
        if score >= thresholds.get("A+", 95):
            return "A+"
        elif score >= thresholds.get("A", 90):
            return "A"
        elif score >= thresholds.get("A-", 85):
            return "A-"
        elif score >= thresholds.get("B+", 80):
            return "B+"
        elif score >= thresholds.get("B", 75):
            return "B"
        elif score >= thresholds.get("B-", 70):
            return "B-"
        elif score >= thresholds.get("C+", 65):
            return "C+"
        elif score >= thresholds.get("C", 60):
            return "C"
        elif score >= thresholds.get("D", 50):
            return "D"
        else:
            return "F"


# ---------------------------------------------------------------------------
# Report Generation
# ---------------------------------------------------------------------------
class ReportGenerator:
    """
    Generates various report formats from KPI computation results.
    """

    def __init__(self, kpi_results: dict):
        self.results = kpi_results

    def generate_json_report(self, output_path: Path) -> None:
        """Write full JSON KPI report."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(self.results, fh, indent=2)
        print(f"[OK] JSON report written to: {output_path}")

    def generate_markdown_report(self, output_path: Path) -> None:
        """Generate a Markdown vendor comparison report."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        summary = self.results["summary"]
        meta = self.results["report_metadata"]
        cm = self.results["confusion_matrix"]
        cats = self.results["category_breakdown"]
        ai = self.results["ai_capability_scores"]

        lines = [
            f"# AppSec Benchmark Report: {meta['vendor_name']}",
            "",
            f"**Generated**: {meta['generated_at']}  ",
            f"**Benchmark Version**: {meta['benchmark_version']}  ",
            f"**Scenarios Evaluated**: {meta['total_benchmarks_evaluated']}",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            f"| Metric | Score |",
            f"|--------|-------|",
            f"| **Composite Score** | **{summary['composite_score']}/100** |",
            f"| **Grade** | **{summary['grade']}** |",
            f"| Precision | {summary['precision']:.2%} |",
            f"| Recall (Detection Coverage) | {summary['recall']:.2%} |",
            f"| Accuracy | {summary['accuracy']:.2%} |",
            f"| F1 Score | {summary['f1_score']:.2%} |",
            f"| False Positive Rate | {summary['false_positive_rate']:.2%} |",
            f"| False Negative Rate | {summary['false_negative_rate']:.2%} |",
            f"| Severity Accuracy | {summary['severity_accuracy']:.2%} |",
            "",
            "---",
            "",
            "## Confusion Matrix",
            "",
            f"| | Predicted Positive | Predicted Negative |",
            f"|---|---|---|",
            f"| **Actually Vulnerable** | TP: {cm['true_positives']} | FN: {cm['false_negatives']} |",
            f"| **Actually Safe** | FP: {cm['false_positives']} | TN: {cm['true_negatives']} |",
            "",
            "---",
            "",
            "## Category Breakdown",
            "",
            "| Category | Benchmarks | Precision | Recall | F1 | FPR |",
            "|----------|-----------|-----------|--------|-----|-----|",
        ]

        for cat in CATEGORIES:
            if cat in cats:
                c = cats[cat]
                lines.append(
                    f"| {cat} | {c['total_benchmarks']} | "
                    f"{c['precision']:.2%} | {c['recall']:.2%} | "
                    f"{c['f1_score']:.2%} | {c['false_positive_rate']:.2%} |"
                )

        lines.extend([
            "",
            "---",
            "",
            "## AI Capability Scores",
            "",
            "| Capability | Applicable | Correct | Score |",
            "|-----------|-----------|---------|-------|",
        ])

        for key, val in ai.items():
            display_name = key.replace("_", " ").title()
            lines.append(
                f"| {display_name} | {val['applicable_count']} | "
                f"{val['correct_count']} | {val['score']:.2%} |"
            )

        lines.extend([
            "",
            "---",
            "",
            f"*Report generated by Enterprise AppSec Benchmark Suite v{meta['benchmark_version']}*",
        ])

        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        print(f"[OK] Markdown report written to: {output_path}")

    def generate_dashboard_data(self, output_dir: Path) -> None:
        """
        Generate structured JSON files optimized for dashboard consumption.
        Splits data into digestible chunks for frontend rendering.
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        summary = self.results["summary"]
        meta = self.results["report_metadata"]

        # 1. Summary card data
        summary_card = {
            "vendor": meta["vendor_name"],
            "generated_at": meta["generated_at"],
            "composite_score": summary["composite_score"],
            "grade": summary["grade"],
            "total_evaluated": meta["total_benchmarks_evaluated"],
            "headline_metrics": {
                "precision": summary["precision"],
                "recall": summary["recall"],
                "f1_score": summary["f1_score"],
                "accuracy": summary["accuracy"],
            },
        }
        self._write_json(output_dir / "summary_card.json", summary_card)

        # 2. Radar chart data (per-category F1)
        radar_data = {
            "labels": [],
            "values": [],
        }
        for cat in CATEGORIES:
            if cat in self.results["category_breakdown"]:
                radar_data["labels"].append(cat)
                radar_data["values"].append(
                    self.results["category_breakdown"][cat]["f1_score"]
                )
        self._write_json(output_dir / "radar_chart.json", radar_data)

        # 3. Confusion matrix for heatmap
        cm = self.results["confusion_matrix"]
        heatmap_data = {
            "matrix": [
                [cm["true_positives"], cm["false_negatives"]],
                [cm["false_positives"], cm["true_negatives"]],
            ],
            "row_labels": ["Actually Vulnerable", "Actually Safe"],
            "col_labels": ["Predicted Positive", "Predicted Negative"],
        }
        self._write_json(output_dir / "confusion_heatmap.json", heatmap_data)

        # 4. Category bar chart data
        bar_data = {
            "categories": [],
            "precision": [],
            "recall": [],
            "f1": [],
        }
        for cat in CATEGORIES:
            if cat in self.results["category_breakdown"]:
                c = self.results["category_breakdown"][cat]
                bar_data["categories"].append(cat)
                bar_data["precision"].append(c["precision"])
                bar_data["recall"].append(c["recall"])
                bar_data["f1"].append(c["f1_score"])
        self._write_json(output_dir / "category_bars.json", bar_data)

        # 5. AI capability spider data
        ai_spider = {
            "labels": [],
            "scores": [],
        }
        for key, val in self.results["ai_capability_scores"].items():
            ai_spider["labels"].append(key.replace("_", " ").title())
            ai_spider["scores"].append(val["score"])
        self._write_json(output_dir / "ai_capability_spider.json", ai_spider)

        # 6. CWE treemap data
        cwe_data = []
        for cwe, vals in self.results.get("cwe_breakdown", {}).items():
            cwe_data.append({
                "cwe": cwe,
                "total": vals["total_benchmarks"],
                "f1": vals["f1_score"],
                "precision": vals["precision"],
                "recall": vals["recall"],
            })
        self._write_json(output_dir / "cwe_treemap.json", cwe_data)

        print(f"[OK] Dashboard data written to: {output_dir}")

    @staticmethod
    def _write_json(path: Path, data: Any) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)


# ---------------------------------------------------------------------------
# Multi-Vendor Comparison
# ---------------------------------------------------------------------------
class VendorComparator:
    """
    Compares KPI results across multiple vendors.
    """

    def __init__(self):
        self.vendor_results: dict[str, dict] = {}

    def add_vendor(self, vendor_name: str, kpi_results: dict) -> None:
        self.vendor_results[vendor_name] = kpi_results

    def generate_comparison(self) -> dict:
        """Generate a side-by-side comparison of all vendors."""
        comparison = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "vendors_compared": list(self.vendor_results.keys()),
            "rankings": {},
            "metric_comparison": {},
        }

        # Compare core metrics
        metrics = [
            "composite_score", "precision", "recall", "accuracy",
            "f1_score", "false_positive_rate", "false_negative_rate",
            "severity_accuracy", "detection_coverage",
        ]

        for metric in metrics:
            comparison["metric_comparison"][metric] = {}
            for vendor, result in self.vendor_results.items():
                comparison["metric_comparison"][metric][vendor] = \
                    result["summary"].get(metric, 0.0)

        # Rank by composite score
        ranked = sorted(
            self.vendor_results.items(),
            key=lambda x: x[1]["summary"]["composite_score"],
            reverse=True,
        )
        comparison["rankings"]["overall"] = [
            {"rank": i + 1, "vendor": v, "score": r["summary"]["composite_score"]}
            for i, (v, r) in enumerate(ranked)
        ]

        # Category-level rankings
        for cat in CATEGORIES:
            cat_rankings = []
            for vendor, result in self.vendor_results.items():
                cat_data = result.get("category_breakdown", {}).get(cat, {})
                if cat_data:
                    cat_rankings.append({
                        "vendor": vendor,
                        "f1": cat_data.get("f1_score", 0.0),
                        "recall": cat_data.get("recall", 0.0),
                    })
            cat_rankings.sort(key=lambda x: x["f1"], reverse=True)
            comparison["rankings"][cat] = [
                {"rank": i + 1, **entry}
                for i, entry in enumerate(cat_rankings)
            ]

        return comparison

    def generate_comparison_report(self, output_path: Path) -> None:
        """Generate a Markdown comparison report."""
        comp = self.generate_comparison()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        lines = [
            "# AppSec Vendor Comparison Report",
            "",
            f"**Generated**: {comp['generated_at']}  ",
            f"**Vendors Compared**: {', '.join(comp['vendors_compared'])}",
            "",
            "---",
            "",
            "## Overall Rankings",
            "",
            "| Rank | Vendor | Composite Score |",
            "|------|--------|----------------|",
        ]

        for entry in comp["rankings"]["overall"]:
            lines.append(f"| {entry['rank']} | {entry['vendor']} | {entry['score']} |")

        lines.extend([
            "",
            "---",
            "",
            "## Metric Comparison",
            "",
        ])

        vendors = comp["vendors_compared"]
        header = "| Metric | " + " | ".join(vendors) + " |"
        sep = "|--------|" + "|".join(["--------" for _ in vendors]) + "|"
        lines.extend([header, sep])

        for metric, values in comp["metric_comparison"].items():
            display = metric.replace("_", " ").title()
            row = f"| {display} | "
            cells = []
            for v in vendors:
                val = values.get(v, 0.0)
                if isinstance(val, float) and val <= 1.0 and metric != "composite_score":
                    cells.append(f"{val:.2%}")
                else:
                    cells.append(f"{val}")
            row += " | ".join(cells) + " |"
            lines.append(row)

        lines.extend([
            "",
            "---",
            "",
            "## Category Rankings",
            "",
        ])

        for cat in CATEGORIES:
            if cat in comp["rankings"] and comp["rankings"][cat]:
                lines.extend([
                    f"### {cat}",
                    "",
                    "| Rank | Vendor | F1 Score | Recall |",
                    "|------|--------|----------|--------|",
                ])
                for entry in comp["rankings"][cat]:
                    lines.append(
                        f"| {entry['rank']} | {entry['vendor']} | "
                        f"{entry['f1']:.2%} | {entry['recall']:.2%} |"
                    )
                lines.append("")

        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        print(f"[OK] Comparison report written to: {output_path}")


# ---------------------------------------------------------------------------
# Demo / Synthetic Data Generator
# ---------------------------------------------------------------------------
def generate_demo_results(expected_findings: list[dict]) -> list[dict]:
    """
    Generate synthetic scan results for demonstration / validation.
    Simulates a vendor with ~75% TP detection, ~10% FP rate.
    """
    import random
    random.seed(42)

    results = []
    for finding in expected_findings:
        bid = finding["benchmark_id"]
        detection = finding.get("expected_detection", "TRUE_POSITIVE")

        if detection == "TRUE_POSITIVE":
            # 75% chance of detecting true vulnerabilities
            detected = random.random() < 0.75
        else:
            # 10% chance of false positive on safe code
            detected = random.random() < 0.10

        if detected:
            # Sometimes get severity wrong (80% accuracy)
            severity = finding.get("expected_severity", "MEDIUM")
            if random.random() > 0.80:
                sev_options = ["HIGH", "MEDIUM", "LOW", "CRITICAL"]
                severity = random.choice([s for s in sev_options if s != severity] or sev_options)

            results.append({
                "benchmark_id": bid,
                "detected_cwe": finding.get("expected_cwe", ""),
                "detected_severity": severity,
                "detected": True,
                "rule_id": f"RULE-{bid}",
                "message": f"Detected vulnerability in {bid}",
            })

    return results


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Enterprise AppSec Benchmark Suite - KPI Calculator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--scan-results",
        type=str,
        help="Path to scan results file",
    )
    parser.add_argument(
        "--format",
        choices=["sarif", "json", "csv"],
        default="json",
        help="Format of the scan results file",
    )
    parser.add_argument(
        "--vendor",
        type=str,
        default="Unknown Vendor",
        help="Name of the vendor being evaluated",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=str(REPORT_OUTPUT_DIR),
        help="Directory for output reports",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run with synthetic demo data for validation",
    )

    args = parser.parse_args()

    # Load ground truth data
    print("[*] Loading ground truth data...")
    expected_findings = load_expected_findings()
    vuln_register = load_vulnerability_register()
    capabilities = load_capability_mapping()
    rubric = load_scoring_rubric()

    print(f"    - Expected findings: {len(expected_findings)}")
    print(f"    - Vulnerability register: {len(vuln_register)}")
    print(f"    - Capabilities: {len(capabilities)}")

    # Parse or generate scan results
    if args.demo:
        print("[*] Running in DEMO mode with synthetic data...")
        scan_results = generate_demo_results(expected_findings)
        vendor_name = "Demo Vendor (Synthetic)"
    elif args.scan_results:
        print(f"[*] Parsing scan results from: {args.scan_results}")
        parse_fn = PARSERS[args.format]
        scan_results = parse_fn(args.scan_results)
        vendor_name = args.vendor
    else:
        print("[!] No scan results provided. Use --scan-results or --demo.")
        print("    Running in DEMO mode for validation...")
        scan_results = generate_demo_results(expected_findings)
        vendor_name = "Demo Vendor (Synthetic)"

    print(f"    - Scan results parsed: {len(scan_results)}")

    # Compute KPIs
    print("[*] Computing KPIs...")
    calculator = KPICalculator(expected_findings, vuln_register, capabilities, rubric)
    results = calculator.compute(scan_results, vendor_name)

    # Generate reports
    output_dir = Path(args.output_dir)
    report_gen = ReportGenerator(results)

    print("[*] Generating reports...")
    report_gen.generate_json_report(output_dir / f"kpi_report_{vendor_name.lower().replace(' ', '_')}.json")
    report_gen.generate_markdown_report(output_dir / f"kpi_report_{vendor_name.lower().replace(' ', '_')}.md")
    report_gen.generate_dashboard_data(output_dir / "dashboard-data")

    # Print summary
    s = results["summary"]
    cm = results["confusion_matrix"]
    print("\n" + "=" * 60)
    print(f"  BENCHMARK RESULTS: {vendor_name}")
    print("=" * 60)
    print(f"  Composite Score : {s['composite_score']}/100  (Grade: {s['grade']})")
    print(f"  Precision       : {s['precision']:.2%}")
    print(f"  Recall          : {s['recall']:.2%}")
    print(f"  F1 Score        : {s['f1_score']:.2%}")
    print(f"  Accuracy        : {s['accuracy']:.2%}")
    print(f"  FP Rate         : {s['false_positive_rate']:.2%}")
    print(f"  FN Rate         : {s['false_negative_rate']:.2%}")
    print(f"  Sev. Accuracy   : {s['severity_accuracy']:.2%}")
    print(f"  TP: {cm['true_positives']}  TN: {cm['true_negatives']}  "
          f"FP: {cm['false_positives']}  FN: {cm['false_negatives']}")
    print("=" * 60)

    return results


if __name__ == "__main__":
    main()
