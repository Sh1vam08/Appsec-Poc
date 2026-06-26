# Benchmark Design Strategy

## 1. Design Philosophy

The Enterprise AppSec Benchmark Suite follows a **capability-driven, control-pair** design philosophy that prioritizes:

1. **Determinism** — Every scenario has a single, unambiguous expected outcome
2. **Traceability** — Every scenario can be traced from source code to ground truth to KPI
3. **Completeness** — No orphan scenarios, no orphan capabilities, no partial implementations
4. **Realism** — Scenarios reflect real-world vulnerability patterns found in enterprise Java applications
5. **Fairness** — Control pairs ensure scanners are evaluated for both detection AND precision

---

## 2. Control Pair Design

### 2.1 Four-Variant Model

For each major vulnerability class, four structurally similar variants are created:

| Variant | Purpose | Expected Scanner Behavior |
|---------|---------|--------------------------|
| **Vulnerable** | True Positive validation | Scanner MUST detect and report |
| **Safe** | False Positive validation | Scanner MUST NOT report (correctly sanitized) |
| **Unreachable** | Reachability validation | Scanner SHOULD suppress or flag as unreachable |
| **Framework-Protected** | Framework awareness validation | Scanner SHOULD recognize framework protection |

### 2.2 Structural Similarity

All four variants in a control pair must:
- Use the same vulnerability class
- Have similar code structure
- Use the same data flow pattern
- Differ ONLY in the presence/absence of the vulnerability

This ensures that detection differences are due to scanner capability, not structural differences.

### 2.3 Endpoint Conventions

| Variant | URL Pattern | HTTP Method |
|---------|------------|-------------|
| Vulnerable | `/api/vulnerable/{vuln-class}` | GET/POST |
| Safe | `/api/safe/{vuln-class}` | GET/POST |
| Unreachable | (no endpoint — dead code) | N/A |
| Framework-Protected | `/api/framework-protected/{vuln-class}` | GET/POST |

### 2.4 Unreachable Mechanisms

Unreachable scenarios use deterministic unreachable patterns:

```java
// Pattern 1: Private method with no callers
private String unreachableSqli(String input) {
    return jdbcTemplate.queryForObject("SELECT * FROM users WHERE id = '" + input + "'", String.class);
}

// Pattern 2: Dead code behind impossible condition
if (1 == 2) {
    jdbcTemplate.execute("SELECT * FROM users WHERE id = '" + input + "'");
}

// Pattern 3: Unregistered Spring bean
// Class exists but is never registered as a @Component/@Service/@Bean

// Pattern 4: Feature flag permanently disabled
@ConditionalOnProperty(name = "benchmark.unreachable.enabled", havingValue = "true")
// Property is always false in application config
```

---

## 3. Vulnerability Scenario Design

### 3.1 SAST Scenarios (~80)

SAST scenarios are organized by vulnerability class. Each class gets a control pair (4 variants). Target: ~20 vulnerability classes × 4 variants = ~80 scenarios.

**Injection Family** (28 scenarios = 7 classes × 4 variants):
- SQL Injection, NoSQL Injection, Command Injection, LDAP Injection, XPath Injection, XML Injection/XXE, SpEL Injection

**Cross-Site Scripting Family** (12 scenarios = 3 classes × 4 variants):
- Stored XSS, Reflected XSS, DOM-based XSS

**Server-Side Flaws** (12 scenarios = 3 classes × 4 variants):
- SSRF, Open Redirect, Path Traversal

**Deserialization & Reflection** (8 scenarios = 2 classes × 4 variants):
- Unsafe Deserialization, Unsafe Reflection

**Authentication & Authorization** (8 scenarios = 2 classes × 4 variants):
- Broken Authentication, Broken Authorization

**Cryptography** (8 scenarios = 2 classes × 4 variants):
- Weak Cryptography, Weak Hashing

**Data & Configuration** (4+ scenarios):
- Hardcoded Credentials, Sensitive Logging, Mass Assignment, Info Disclosure, Session Management, Cookie Security, JWT Misconfigurations, CSRF, File Upload, Race Conditions, Business Logic, Trust Boundary, API Security, Security Misconfiguration

### 3.2 SCA Scenarios (~40)

SCA scenarios are organized by dependency type and reachability:

**Direct Dependencies — Vulnerable & Reachable** (~10):
- Log4j 2.14.1, Jackson Databind 2.9.8, SnakeYAML 1.26, Commons Collections 3.2.1, Spring Core (specific CVE versions)

**Direct Dependencies — Vulnerable & Unreachable** (~10):
- Same libraries, vulnerable code paths not invoked

**Transitive Dependencies — Vulnerable & Reachable** (~10):
- Vulnerabilities pulled in transitively through parent dependencies

**Transitive Dependencies — Vulnerable & Unreachable** (~10):
- Transitive vulnerabilities with non-reachable code paths

### 3.3 DAST Scenarios (~20)

Every DAST scenario has a complete data flow: Controller → Service → Repository → Sink

- SQL Injection endpoints (2)
- XSS endpoints (2)
- CSRF endpoints (2)
- SSRF endpoints (2)
- Open Redirect endpoints (2)
- Path Traversal endpoints (2)
- File Upload endpoints (2)
- Authentication weakness endpoints (2)
- Authorization weakness endpoints (2)
- API security endpoints (2)

### 3.4 Secret Scanning Scenarios (~30)

Secrets embedded across multiple file formats:

| Format | Scenario Count |
|--------|---------------|
| Java source code | 6 |
| YAML files | 4 |
| JSON files | 3 |
| Properties files | 3 |
| Environment files | 3 |
| Terraform files | 3 |
| Dockerfiles | 3 |
| CI/CD pipelines | 3 |
| Kubernetes manifests | 2 |

### 3.5 Container Security Scenarios (~20)

10 vulnerable Dockerfiles + 10 safe counterparts:
- Root user, privilege escalation, dangerous capabilities, outdated images, exposed secrets, weak runtime config, excessive surface, missing health checks, package vulns, weak permissions

### 3.6 IaC Security Scenarios (~20)

10 vulnerable + 10 safe configurations across Terraform and Kubernetes:
- Public S3, public DB, weak SGs, excessive IAM, missing encryption, missing logging, weak segmentation, dangerous RBAC, privileged pods, hostPath mounts

---

## 4. Traceability Design

Every benchmark scenario maintains a full traceability chain:

```
Source Code (// BENCH-SAST-001)
    ↓
benchmark_manifest.json (benchmark_id: BENCH-SAST-001)
    ↓
vulnerability_register.json (benchmark_id: BENCH-SAST-001)
    ↓
capability_mapping.json (benchmark_ids: [BENCH-SAST-001])
    ↓
expected_findings.json (benchmark_id: BENCH-SAST-001)
    ↓
KPI Calculation (input: expected vs actual findings)
```

### 4.1 Inline Identifiers

Every benchmark scenario contains an inline comment identifier:

```java
// BENCH-SAST-001: SQL Injection — Vulnerable variant
// BENCH-SAST-002: SQL Injection — Safe variant
// BENCH-SAST-003: SQL Injection — Unreachable variant
// BENCH-SAST-004: SQL Injection — Framework-Protected variant
```

### 4.2 Cross-Reference Integrity

The following invariants must always hold:
- Every `benchmark_id` in `benchmark_manifest.json` exists in `vulnerability_register.json`
- Every `benchmark_id` in `benchmark_manifest.json` exists in `expected_findings.json`
- Every `capability_id` in `capability_mapping.json` has at least one `benchmark_id`
- Every `benchmark_id` in code has a matching entry in all register files

---

## 5. Naming Conventions

### 5.1 Java Classes
```
{VulnClass}{Variant}Controller.java    — e.g., SqlInjectionVulnerableController.java
{VulnClass}{Variant}Service.java       — e.g., SqlInjectionVulnerableService.java
{VulnClass}{Variant}Repository.java    — e.g., SqlInjectionVulnerableRepository.java
```

Or grouped by vulnerability class with variant methods inside.

### 5.2 Endpoints
```
/api/vulnerable/{vuln-class}          — Vulnerable variant
/api/safe/{vuln-class}                — Safe variant
/api/framework-protected/{vuln-class} — Framework-protected variant
```

### 5.3 Files
```
terraform/aws/vulnerable/{resource}.tf
terraform/aws/safe/{resource}.tf
container/vulnerable/Dockerfile.{scenario}
container/safe/Dockerfile.{scenario}
```

---

## 6. AI Feature Evaluation Strategy

AI capabilities are evaluated using benchmark scenarios from all categories. The evaluation measures:

| AI Feature | Evaluation Method | Input |
|-----------|-------------------|-------|
| Fix Generation | Feed vulnerability to AI, validate generated fix compiles and resolves the issue | Vulnerable variant code |
| Remediation Guidance | Compare AI guidance against expected_remediation field | Vulnerability finding |
| Root Cause Analysis | Compare AI root cause against expected_root_cause field | Vulnerability finding |
| Reachability Analysis | Compare AI reachability against expected_reachability field | Unreachable variants |
| Prioritization | Compare AI priority ranking against expected severity/risk | All findings |
| Risk Ranking | Compare AI risk score against expected_risk_rating field | All findings |
| Executive Summary | Evaluate summary completeness and accuracy | Full scan results |
| Code Explanation | Evaluate explanation accuracy against known vulnerability pattern | Vulnerable variant code |
