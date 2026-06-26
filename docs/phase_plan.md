# Phase Execution Plan

## Overview

The benchmark suite is built across 11 phases (Phase 0–10). Each phase is atomic — it produces complete, usable deliverables. Phases are executed sequentially with explicit approval gates between them.

---

## Phase 0: Architecture and Planning ✅ (Current Phase)

**Objective**: Establish the complete architectural foundation, repository structure, and state management schemas.

**Deliverables**:
| Deliverable | Path | Status |
|------------|------|--------|
| Project State Schema | `benchmark-state/project_state.json` | ✅ |
| Phase Status Schema | `benchmark-state/phase_status.json` | ✅ |
| Progress Tracker Schema | `benchmark-state/progress_tracker.json` | ✅ |
| Vulnerability Register Schema | `benchmark-state/vulnerability_register.json` | ✅ |
| Capability Mapping Schema | `benchmark-state/capability_mapping.json` | ✅ |
| Expected Findings Schema | `benchmark-state/expected_findings.json` | ✅ |
| Benchmark Manifest Schema | `benchmark-state/benchmark_manifest.json` | ✅ |
| Architecture Document | `docs/architecture.md` | ✅ |
| Repository Structure | `docs/repository_structure.md` | ✅ |
| Capability Strategy | `docs/capability_strategy.md` | ✅ |
| Benchmark Strategy | `docs/benchmark_strategy.md` | ✅ |
| Phase Plan | `docs/phase_plan.md` | ✅ |

**Exit Criteria**: All state file schemas created with valid empty structures. All documentation complete.

---

## Phase 1: Ground Truth Framework

**Objective**: Populate all ground truth registry files with complete entries for all ~210 benchmark scenarios.

**Deliverables**:
| Deliverable | Description |
|------------|-------------|
| `vulnerability_register.json` | Full entries for all ~210 scenarios |
| `capability_mapping.json` | Full capability definitions with benchmark mappings |
| `expected_findings.json` | Deterministic expected outcomes for all scenarios |
| `benchmark_manifest.json` | Complete manifest of all planned benchmark assets |
| `benchmark_catalog.json` | Human-readable catalog of all benchmark scenarios |

**Estimated Work**:
- ~210 vulnerability register entries
- ~80+ capability mapping entries
- ~210 expected finding entries
- ~210 manifest entries

**Exit Criteria**: All registries populated. Cross-reference integrity validated. No orphan records.

---

## Phase 2: Core Spring Boot Skeleton

**Objective**: Create a runnable Spring Boot application with all infrastructure code. No vulnerabilities.

**Deliverables**:
| Deliverable | Description |
|------------|-------------|
| `pom.xml` | Maven POM with safe dependency versions |
| `ShopSphereApplication.java` | Main application entry point |
| `SecurityConfig.java` | Spring Security configuration |
| `WebConfig.java` | Web MVC configuration |
| `DataSourceConfig.java` | Data source configuration |
| `FeatureFlagConfig.java` | Feature flag configuration |
| `application.properties` | Application configuration |
| `schema.sql` | Database schema |
| `data.sql` | Seed data |
| Base entities and DTOs | Core data model |
| `Dockerfile` | Application container |
| `docker-compose.yml` | Local development setup |
| `.gitignore` | Git ignore rules |
| `README.md` | Project documentation |

**Exit Criteria**: Application compiles. `mvn clean package` succeeds. Docker image builds. Application starts and serves health endpoint.

---

## Phase 3: SAST Benchmark Scenarios

**Objective**: Implement ~80 SAST benchmark scenarios with full control pairs.

**Sub-phases** (to manage output window):
| Sub-phase | Scenarios | IDs |
|-----------|-----------|-----|
| 3a | Injection Family (SQL, NoSQL, Cmd, LDAP, XPath, XML/XXE, SpEL) | BENCH-SAST-001 to BENCH-SAST-028 |
| 3b | XSS Family (Stored, Reflected, DOM) | BENCH-SAST-029 to BENCH-SAST-040 |
| 3c | Server-Side (SSRF, Redirect, Traversal) | BENCH-SAST-041 to BENCH-SAST-052 |
| 3d | Deserialization, Reflection, OGNL | BENCH-SAST-053 to BENCH-SAST-060 |
| 3e | Auth, Crypto, Data, Config | BENCH-SAST-061 to BENCH-SAST-080 |

**For Each Scenario**:
- Controller class with vulnerability/safe/unreachable/protected variants
- Service class with business logic
- Repository class for data access
- Inline `// BENCH-SAST-NNN` identifiers
- Update state files

**Exit Criteria**: All ~80 SAST scenarios implemented. All state files updated. All inline IDs present.

---

## Phase 4: DAST Benchmark Scenarios

**Objective**: Implement ~20 DAST benchmark scenarios with full data flows.

**Scenarios**:
| ID Range | Category | Count |
|----------|----------|-------|
| BENCH-DAST-001 to BENCH-DAST-002 | SQL Injection | 2 |
| BENCH-DAST-003 to BENCH-DAST-004 | XSS | 2 |
| BENCH-DAST-005 to BENCH-DAST-006 | CSRF | 2 |
| BENCH-DAST-007 to BENCH-DAST-008 | SSRF | 2 |
| BENCH-DAST-009 to BENCH-DAST-010 | Open Redirect | 2 |
| BENCH-DAST-011 to BENCH-DAST-012 | Path Traversal | 2 |
| BENCH-DAST-013 to BENCH-DAST-014 | File Upload | 2 |
| BENCH-DAST-015 to BENCH-DAST-016 | Authentication | 2 |
| BENCH-DAST-017 to BENCH-DAST-018 | Authorization | 2 |
| BENCH-DAST-019 to BENCH-DAST-020 | API Security | 2 |

**For Each Scenario**:
- Controller → Service → Repository → Sink data flow
- Exploit path documentation
- Expected request/response
- Inline identifiers

**Exit Criteria**: All 20 DAST scenarios implemented with complete data flows. All endpoints externally reachable.

---

## Phase 5: SCA Benchmark Scenarios

**Objective**: Configure ~40 SCA benchmark scenarios via Maven dependencies.

**Scenarios**:
| ID Range | Category | Count |
|----------|----------|-------|
| BENCH-SCA-001 to BENCH-SCA-010 | Direct — Reachable | 10 |
| BENCH-SCA-011 to BENCH-SCA-020 | Direct — Unreachable | 10 |
| BENCH-SCA-021 to BENCH-SCA-030 | Transitive — Reachable | 10 |
| BENCH-SCA-031 to BENCH-SCA-040 | Transitive — Unreachable | 10 |

**For Each Scenario**:
- Maven dependency entry
- Code that uses (or does not use) the vulnerable API
- Inline identifiers

**Exit Criteria**: All 40 SCA scenarios implemented. pom.xml contains all vulnerable dependencies. Reachability paths documented.

---

## Phase 6: Secret Scanning Benchmark

**Objective**: Embed ~30 realistic secret patterns across multiple file formats.

**Scenarios**:
| ID Range | Secret Type | Format | Count |
|----------|------------|--------|-------|
| BENCH-SECRET-001 to BENCH-SECRET-006 | AWS, GitHub, GitLab, Slack, Azure, GCP | Source Code | 6 |
| BENCH-SECRET-007 to BENCH-SECRET-010 | Various | YAML | 4 |
| BENCH-SECRET-011 to BENCH-SECRET-013 | Various | JSON | 3 |
| BENCH-SECRET-014 to BENCH-SECRET-016 | Various | Properties | 3 |
| BENCH-SECRET-017 to BENCH-SECRET-019 | Various | Env Files | 3 |
| BENCH-SECRET-020 to BENCH-SECRET-022 | Various | Terraform | 3 |
| BENCH-SECRET-023 to BENCH-SECRET-025 | Various | Docker | 3 |
| BENCH-SECRET-026 to BENCH-SECRET-028 | Various | CI/CD | 3 |
| BENCH-SECRET-029 to BENCH-SECRET-030 | SSH/Cert | K8s Manifests | 2 |

**Exit Criteria**: All 30 secret scenarios embedded with realistic patterns.

---

## Phase 7: Container Security Benchmark

**Objective**: Create ~20 container security scenarios.

**Scenarios**:
| ID Range | Category | Count |
|----------|----------|-------|
| BENCH-CONTAINER-001/002 | Root User | 2 (vuln + safe) |
| BENCH-CONTAINER-003/004 | Privilege Escalation | 2 |
| BENCH-CONTAINER-005/006 | Dangerous Capabilities | 2 |
| BENCH-CONTAINER-007/008 | Outdated Base Images | 2 |
| BENCH-CONTAINER-009/010 | Exposed Secrets | 2 |
| BENCH-CONTAINER-011/012 | Weak Runtime Config | 2 |
| BENCH-CONTAINER-013/014 | Excessive Attack Surface | 2 |
| BENCH-CONTAINER-015/016 | Missing Health Checks | 2 |
| BENCH-CONTAINER-017/018 | Package Vulnerabilities | 2 |
| BENCH-CONTAINER-019/020 | Weak File Permissions | 2 |

**Exit Criteria**: All 20 container scenarios created as Dockerfiles.

---

## Phase 8: IaC Security Benchmark

**Objective**: Create ~20 IaC security scenarios.

**Scenarios**:
| ID Range | Category | Count |
|----------|----------|-------|
| BENCH-IAC-001/002 | Public S3 Bucket | 2 (vuln + safe) |
| BENCH-IAC-003/004 | Public Database | 2 |
| BENCH-IAC-005/006 | Weak Security Groups | 2 |
| BENCH-IAC-007/008 | Excessive IAM | 2 |
| BENCH-IAC-009/010 | Missing Encryption | 2 |
| BENCH-IAC-011/012 | Missing Logging | 2 |
| BENCH-IAC-013/014 | Weak Segmentation | 2 |
| BENCH-IAC-015/016 | Dangerous RBAC | 2 |
| BENCH-IAC-017/018 | Privileged Containers (K8s) | 2 |
| BENCH-IAC-019/020 | HostPath Mounts (K8s) | 2 |

**Exit Criteria**: All 20 IaC scenarios created as Terraform/K8s manifests.

---

## Phase 9: CI/CD Security Benchmark

**Objective**: Create CI/CD security benchmark scenarios.

**Deliverables**:
- GitHub Actions workflows (vulnerable + safe variants)
- Jenkins pipeline examples (vulnerable + safe variants)
- Secret injection patterns
- Dependency confusion patterns
- Unsafe action usage patterns

**Exit Criteria**: CI/CD benchmark files created and registered.

---

## Phase 10: KPI Framework

**Objective**: Create the KPI calculation and scoring framework.

**Deliverables**:
| Deliverable | Description |
|------------|-------------|
| KPI Calculator | Script to calculate all KPIs from scan results vs expected findings |
| Report Templates | Templates for vendor comparison reports |
| Scoring Rubric | Weighted scoring methodology |
| Executive Dashboard Data | Data structure for executive dashboards |
| Documentation | Complete KPI framework documentation |

**Exit Criteria**: KPI framework can ingest scan results and produce all defined metrics.

---

## Resume Protocol

When resuming from any interruption:

1. Read `benchmark-state/phase_status.json` to determine current phase
2. Read `benchmark-state/progress_tracker.json` to determine completed items
3. Read `benchmark-state/benchmark_manifest.json` to verify registered assets
4. Continue from the first incomplete item in the current phase
5. Never regenerate completed work
6. Preserve all existing benchmark IDs
