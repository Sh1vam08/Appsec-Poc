# Enterprise AppSec Benchmark Suite — Architecture Document

## 1. Overview

The Enterprise AppSec Benchmark Suite is a purpose-built, runnable Java Spring Boot application designed to provide a comprehensive, deterministic, and traceable set of security benchmark scenarios. It serves as the authoritative test corpus for evaluating enterprise Application Security (AppSec) platforms across all major scanning modalities.

### Target Platforms
- Snyk
- Checkmarx
- Wiz
- Veracode
- GitHub Advanced Security (GHAS)
- Semgrep
- SonarQube
- Any enterprise AppSec tool supporting SAST, SCA, DAST, IaC, Container, or Secret scanning

### Evaluation Dimensions
| Dimension | Scenario Count | Phase |
|-----------|---------------|-------|
| SAST | ~80 | Phase 3 |
| SCA | ~40 | Phase 5 |
| DAST | ~20 | Phase 4 |
| Secret Scanning | ~30 | Phase 6 |
| Container Security | ~20 | Phase 7 |
| IaC Security | ~20 | Phase 8 |
| **Total** | **~210** | |

---

## 2. Technology Stack

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| Language | Java | 17 (LTS) | Primary application language |
| Framework | Spring Boot | 3.2.x | Web application framework |
| Build Tool | Maven | 3.9.x | Dependency management and build |
| Database | H2 | 2.2.x | Embedded DB for portability |
| ORM | Spring Data JPA / Hibernate | 6.x | Data persistence |
| Security | Spring Security | 6.2.x | Authentication/Authorization |
| Template Engine | Thymeleaf | 3.1.x | Server-side rendering (for XSS tests) |
| Serialization | Jackson / SnakeYAML / XMLBeans | Various | Deserialization vulnerability tests |
| Container | Docker | Latest | Container security benchmarks |
| Orchestration | Kubernetes | 1.28+ | K8s manifest benchmarks |
| IaC | Terraform | 1.7.x | Infrastructure-as-Code benchmarks |
| CI/CD | GitHub Actions / Jenkins | Latest | Pipeline security benchmarks |
| API Documentation | SpringDoc OpenAPI | 2.3.x | API documentation |

---

## 3. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Enterprise AppSec Benchmark Suite             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  Benchmark   │  │  Benchmark   │  │  Benchmark           │  │
│  │  App (Java)  │  │  SCA (Maven) │  │  Secrets (Multi-fmt) │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘  │
│         │                 │                      │              │
│  ┌──────┴───────┐  ┌──────┴───────┐  ┌──────────┴───────────┐  │
│  │ Controllers  │  │   pom.xml    │  │  Source Code          │  │
│  │ Services     │  │ Vulnerable   │  │  YAML / JSON          │  │
│  │ Repositories │  │ Dependencies │  │  Terraform / Docker   │  │
│  │ Models       │  │ Direct +     │  │  CI/CD Pipelines      │  │
│  │ Config       │  │ Transitive   │  │  Properties / Env     │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  Benchmark   │  │  Benchmark   │  │  Benchmark           │  │
│  │  IaC         │  │  Container   │  │  Ground Truth + KPI  │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘  │
│         │                 │                      │              │
│  ┌──────┴───────┐  ┌──────┴───────┐  ┌──────────┴───────────┐  │
│  │ Terraform    │  │ Dockerfiles  │  │ vulnerability_register│  │
│  │ K8s Manifests│  │ Compose      │  │ capability_mapping    │  │
│  │ Helm Charts  │  │ K8s Pods     │  │ expected_findings     │  │
│  │ Cloud Configs│  │ Runtime Cfgs │  │ benchmark_manifest    │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                     Benchmark State Engine                       │
│  project_state.json │ phase_status.json │ progress_tracker.json │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. Application Architecture (Spring Boot)

### 4.1 Package Structure
```
com.shopsphere
├── ShopSphereApplication.java             # Main entry point
├── config/                                # Core configurations (Security, MVC, H2)
├── auth/                                  # Authentication and Session security modules
├── cart/                                  # Shopping Cart module
├── catalog/                               # Product Catalog and Inventory modules
├── common/                                # Commons (Redirect, Deserialization)
├── model/                                 # E-Commerce entities and DTOs
├── order/                                 # Orders, Invoices, Checkout modules
├── payment/                               # Cryptography and Payment gateways
├── profile/                               # Customer Profile module
├── reporting/                             # Admin reporting modules
├── repository/                            # Database repositories
├── review/                                # Review comments and feedback modules
├── support/                               # Asset downloads and Profile uploads
├── system/                                # System diagnostics
└── util/                                  # Utilities and helper classes
```

### 4.2 Data Flow Architecture (DAST Requirement)

Every DAST vulnerability follows the unified data flow:

```
HTTP Request → Controller → Service → Repository → Database (Sink)
      ↓              ↓           ↓           ↓
  [Entry Point]  [Routing]  [Business]  [Data Access]
```

No isolated utility vulnerabilities. No dead-end test functions.

### 4.3 Control Pair Architecture

For each major vulnerability class, four structural variants are generated:

| Variant | Endpoint Pattern | Purpose |
|---------|-----------------|---------|
| Vulnerable | `/api/vulnerable/{vuln-class}` | True Positive testing |
| Safe | `/api/safe/{vuln-class}` | False Positive testing |
| Unreachable | (no endpoint — private/dead code) | Reachability validation |
| Framework-Protected | `/api/framework-protected/{vuln-class}` | Framework awareness testing |

---

## 5. Benchmark Identifier Scheme

### 5.1 Benchmark IDs
```
BENCH-{CATEGORY}-{NNN}

Categories: SAST, SCA, DAST, SECRET, CONTAINER, IAC, CICD
NNN: Zero-padded 3-digit sequential number

Examples:
  BENCH-SAST-001
  BENCH-SCA-015
  BENCH-DAST-003
  BENCH-SECRET-022
  BENCH-CONTAINER-007
  BENCH-IAC-011
```

### 5.2 Capability IDs
```
CAP-{CATEGORY}-{VULN_CLASS}-{NNN}

Examples:
  CAP-SAST-SQLI-001
  CAP-SCA-LOG4J-001
  CAP-DAST-XSS-002
  CAP-SECRET-AWS-001
  CAP-CONTAINER-ROOT-001
  CAP-IAC-S3PUB-001
```

### 5.3 Control Pair Group IDs
```
CTRL-{CATEGORY}-{VULN_CLASS}-{NNN}

Examples:
  CTRL-SAST-SQLI-001  (groups BENCH-SAST-001 through BENCH-SAST-004)
```

---

## 6. State Management Architecture

All state is persisted in `benchmark-state/` directory:

| File | Purpose | Updated By |
|------|---------|-----------|
| `project_state.json` | Master project state | Every phase |
| `phase_status.json` | Phase-level status tracking | Every phase |
| `progress_tracker.json` | Item-level completion tracking | Every phase |
| `vulnerability_register.json` | Ground truth vulnerability data | Phase 1+, updated per implementation phase |
| `capability_mapping.json` | Capability-to-benchmark mapping | Phase 1+, updated per implementation phase |
| `expected_findings.json` | Deterministic expected outcomes | Phase 1+, updated per implementation phase |
| `benchmark_manifest.json` | Authoritative asset inventory | Every phase that creates assets |

### Resume Protocol
1. Read all state files
2. Determine completed work from `progress_tracker.json`
3. Determine current phase from `phase_status.json`
4. Continue from first incomplete item
5. Never regenerate completed modules

---

## 7. KPI Measurement Architecture

The benchmark supports the following KPI calculations:

| KPI | Formula | Data Source |
|-----|---------|-------------|
| Detection Coverage | Detected / Total Scenarios | expected_findings.json |
| True Positive Rate | TP / (TP + FN) | Scan results vs expected_findings |
| False Positive Rate | FP / (FP + TN) | Scan results vs expected_findings |
| Precision | TP / (TP + FP) | Scan results vs expected_findings |
| Recall | TP / (TP + FN) | Scan results vs expected_findings |
| Accuracy | (TP + TN) / Total | Scan results vs expected_findings |
| Severity Accuracy | Correct Severity / Total | Scan results vs vulnerability_register |
| Reachability Accuracy | Correct Reachability / Total | Scan results vs vulnerability_register |
| Category Coverage | Category Detected / Category Total | Per-category analysis |

---

## 8. Deployment Architecture

```
┌─────────────────────────┐
│    Docker Compose        │
│                         │
│  ┌───────────────────┐  │
│  │  benchmark-app    │  │
│  │  (Spring Boot)    │  │
│  │  Port: 8080       │  │
│  └───────────────────┘  │
│                         │
│  ┌───────────────────┐  │
│  │  H2 Database      │  │
│  │  (Embedded)       │  │
│  └───────────────────┘  │
└─────────────────────────┘
```

The application runs as a single Docker container with an embedded H2 database for maximum portability. No external database dependencies.

---

## 9. Security Considerations

This benchmark application is **intentionally vulnerable**. It contains real vulnerabilities for testing purposes.

**WARNING**: This application must NEVER be deployed to production or exposed to public networks. It should only be used in isolated, controlled environments for AppSec tool evaluation.

Safeguards:
- Default Spring profile: `benchmark` (not `production`)
- Banner warning on startup
- H2 console disabled by default
- No external network dependencies
- Designed for ephemeral container execution
