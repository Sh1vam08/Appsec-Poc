# Repository Structure

```
enterprise-appsec-benchmark/
│
├── benchmark-state/                              # State management (source of truth)
│   ├── project_state.json                        # Master project state
│   ├── phase_status.json                         # Phase-level tracking
│   ├── progress_tracker.json                     # Item-level tracking
│   ├── vulnerability_register.json               # Ground truth register
│   ├── capability_mapping.json                   # Capability-to-benchmark mapping
│   ├── expected_findings.json                    # Deterministic expected findings
│   └── benchmark_manifest.json                   # Authoritative asset inventory
│
├── docs/                                         # Documentation
│   ├── architecture.md                           # Architecture document
│   ├── repository_structure.md                   # This file
│   ├── capability_strategy.md                    # Capability evaluation strategy
│   ├── benchmark_strategy.md                     # Benchmark design strategy
│   └── phase_plan.md                             # Detailed phase execution plan
│
├── src/                                          # Java Spring Boot Application
│   ├── main/
│   │   ├── java/com/shopsphere/
│   │   │   ├── ShopSphereApplication.java        # Main Spring Boot entry point
│   │   │   ├── config/                           # Application configuration
│   │   │   │   ├── SecurityConfig.java           # Spring Security config
│   │   │   │   ├── WebConfig.java                # Web MVC config
│   │   │   │   ├── DataSourceConfig.java         # Data source config
│   │   │   │   └── FeatureFlagConfig.java        # Feature flags (unreachable scenarios)
│   │   │   ├── auth/                             # Customer registration, login, token auth
│   │   │   ├── cart/                             # Shopping cart and CSRF services
│   │   │   ├── catalog/                          # Product search, catalog lookups, XML imports
│   │   │   ├── common/                           # Open redirect and deserialization helpers
│   │   │   ├── model/                            # Data models and entities
│   │   │   ├── order/                            # Invoice generation, order lookups, PDF exports
│   │   │   ├── payment/                          # Cryptography and payment gateways
│   │   │   ├── profile/                          # User profile updates and data exposure controllers
│   │   │   ├── reporting/                        # Admin settings and reporting dashboards
│   │   │   ├── repository/                       # Data access layer
│   │   │   ├── review/                           # Product review and comment logic
│   │   │   ├── support/                          # Asset downloads and profile upload services
│   │   │   ├── system/                           # System diagnostics services
│   │   │   └── util/                             # Utility classes
│   │   └── resources/
│   │       ├── application.properties            # Main application config
│   │       ├── templates/                        # Thymeleaf templates (for review rendering)
│   │       ├── static/                           # Static resources (ShopSphere dashboard)
│   │       ├── data.sql                          # Initial e-commerce data seeds
│   │       └── schema.sql                        # Database schema
│
├── iac/                                          # Infrastructure-as-Code benchmarks
│   ├── terraform/                                # Terraform benchmarks
│   │   ├── aws/                                  # AWS resources
│   │   │   ├── vulnerable/                       # Vulnerable configurations
│   │   │   └── safe/                             # Safe configurations
│   │   ├── azure/                                # Azure resources
│   │   └── gcp/                                  # GCP resources
│   └── kubernetes/                               # Kubernetes benchmarks
│       ├── deployments/                          # Deployment manifests
│       ├── rbac/                                 # RBAC configurations
│       ├── network-policies/                     # Network policies
│       └── secrets/                              # Secret handling
│
├── container/                                    # Container security benchmarks
│   ├── vulnerable/                               # Vulnerable Dockerfiles
│   ├── safe/                                     # Safe Dockerfiles
│   └── compose/                                  # Docker Compose files
│
├── cicd/                                         # CI/CD security benchmarks
│   ├── github-actions/                           # GitHub Actions workflows
│   │   ├── vulnerable/                           # Vulnerable workflows
│   │   └── safe/                                 # Safe workflows
│   └── jenkins/                                  # Jenkins pipelines
│       ├── vulnerable/                           # Vulnerable Jenkinsfiles
│       └── safe/                                 # Safe Jenkinsfiles
│
├── secrets-benchmark/                            # Secret scanning benchmarks
│   ├── source-code/                              # Secrets in source code
│   ├── config-files/                             # Secrets in config files
│   ├── iac-files/                                # Secrets in IaC files
│   └── cicd-files/                               # Secrets in CI/CD files
│
├── kpi/                                          # KPI framework
│   ├── scoring/                                  # Scoring scripts
│   ├── templates/                                # Report templates
│   └── README.md                                 # KPI framework documentation
│
├── pom.xml                                       # Maven POM (with vulnerable deps for SCA)
├── Dockerfile                                    # Application Dockerfile
├── docker-compose.yml                            # Docker Compose for local development
├── .gitignore                                    # Git ignore rules
└── README.md                                     # Project README
```
