# Capability Evaluation Strategy

## 1. Overview

The Enterprise AppSec Benchmark Suite uses a **capability-driven** design. Every benchmark scenario exists to validate one or more specific capabilities that an AppSec platform should possess. This document defines the capability taxonomy, mapping strategy, and evaluation methodology.

---

## 2. Capability Taxonomy

### 2.1 SAST Capabilities (CAP-SAST-*)

| Capability ID | Name | Description |
|--------------|------|-------------|
| CAP-SAST-SQLI-001 | SQL Injection Detection | Detect SQL injection via string concatenation in JDBC queries |
| CAP-SAST-SQLI-002 | SQL Injection Sanitization Recognition | Recognize parameterized queries as safe |
| CAP-SAST-SQLI-003 | SQL Injection Reachability | Determine reachability of SQL injection sinks |
| CAP-SAST-SQLI-004 | SQL Injection Framework Protection | Recognize Spring Data JPA as framework-protected |
| CAP-SAST-NOSQLI-001 | NoSQL Injection Detection | Detect NoSQL injection in MongoDB queries |
| CAP-SAST-CMDI-001 | Command Injection Detection | Detect OS command injection via Runtime.exec() |
| CAP-SAST-CMDI-002 | Command Injection Sanitization | Recognize input validation as mitigation |
| CAP-SAST-LDAPI-001 | LDAP Injection Detection | Detect LDAP injection in directory queries |
| CAP-SAST-XPATHI-001 | XPath Injection Detection | Detect XPath injection in XML queries |
| CAP-SAST-XMLI-001 | XML Injection Detection | Detect XML injection in document construction |
| CAP-SAST-XXE-001 | XXE Detection | Detect XML External Entity processing |
| CAP-SAST-XXE-002 | XXE Safe Parser Recognition | Recognize disabled external entities as safe |
| CAP-SAST-SSRF-001 | SSRF Detection | Detect Server-Side Request Forgery |
| CAP-SAST-SSRF-002 | SSRF URL Validation Recognition | Recognize URL allowlist validation as safe |
| CAP-SAST-REDIRECT-001 | Open Redirect Detection | Detect unvalidated redirects |
| CAP-SAST-TRAVERSAL-001 | Path Traversal Detection | Detect path traversal via user-controlled file paths |
| CAP-SAST-TRAVERSAL-002 | Path Traversal Canonicalization | Recognize path canonicalization as safe |
| CAP-SAST-REFLECT-001 | Unsafe Reflection Detection | Detect Class.forName() with user input |
| CAP-SAST-SPEL-001 | SpEL Injection Detection | Detect Spring Expression Language injection |
| CAP-SAST-OGNL-001 | OGNL Injection Detection | Detect Object Graph Navigation injection |
| CAP-SAST-DESER-001 | Unsafe Deserialization Detection | Detect ObjectInputStream deserialization of untrusted data |
| CAP-SAST-DESER-002 | Deserialization Type Filter Recognition | Recognize ObjectInputFilter as mitigation |
| CAP-SAST-CREDS-001 | Hardcoded Credentials Detection | Detect hardcoded passwords and API keys |
| CAP-SAST-CREDS-002 | Hardcoded Crypto Key Detection | Detect hardcoded encryption keys |
| CAP-SAST-CRYPTO-001 | Weak Cryptography Detection | Detect use of DES, RC4, ECB mode |
| CAP-SAST-CRYPTO-002 | Weak Hashing Detection | Detect use of MD5, SHA-1 for security purposes |
| CAP-SAST-AUTH-001 | Broken Authentication Detection | Detect weak authentication mechanisms |
| CAP-SAST-AUTHZ-001 | Broken Authorization Detection | Detect missing access control checks |
| CAP-SAST-AUTHZ-002 | Missing Access Control Detection | Detect endpoints without authorization |
| CAP-SAST-DATA-001 | Sensitive Data Exposure Detection | Detect sensitive data in responses |
| CAP-SAST-LOG-001 | Sensitive Logging Detection | Detect PII/secrets in log statements |
| CAP-SAST-SESSION-001 | Session Management Issue Detection | Detect weak session configuration |
| CAP-SAST-COOKIE-001 | Cookie Security Issue Detection | Detect insecure cookie attributes |
| CAP-SAST-INFO-001 | Information Disclosure Detection | Detect stack traces and debug info in responses |
| CAP-SAST-JWT-001 | JWT Misconfiguration Detection | Detect weak JWT signing, missing validation |
| CAP-SAST-MASS-001 | Mass Assignment Detection | Detect uncontrolled binding of request parameters |
| CAP-SAST-UPLOAD-001 | File Upload Vulnerability Detection | Detect unrestricted file upload |
| CAP-SAST-RACE-001 | Race Condition Detection | Detect TOCTOU and concurrent state issues |
| CAP-SAST-LOGIC-001 | Business Logic Vulnerability Detection | Detect logic flaws in business rules |
| CAP-SAST-TRUST-001 | Trust Boundary Violation Detection | Detect trust boundary violations |
| CAP-SAST-XSS-STORED-001 | Stored XSS Detection | Detect stored cross-site scripting |
| CAP-SAST-XSS-REFLECTED-001 | Reflected XSS Detection | Detect reflected cross-site scripting |
| CAP-SAST-XSS-DOM-001 | DOM-based XSS Detection | Detect DOM-based cross-site scripting |
| CAP-SAST-CSRF-001 | CSRF Detection | Detect missing CSRF protections |
| CAP-SAST-API-001 | API Security Weakness Detection | Detect API security misconfigurations |
| CAP-SAST-MISCONFIG-001 | Security Misconfiguration Detection | Detect security misconfigurations |
| CAP-SAST-3RDPARTY-001 | Unsafe Third-Party Usage Detection | Detect unsafe use of third-party components |

### 2.2 SCA Capabilities (CAP-SCA-*)

| Capability ID | Name | Description |
|--------------|------|-------------|
| CAP-SCA-DIRECT-001 | Direct Dependency CVE Detection | Detect known CVEs in direct dependencies |
| CAP-SCA-TRANS-001 | Transitive Dependency CVE Detection | Detect known CVEs in transitive dependencies |
| CAP-SCA-REACH-001 | Reachable Vulnerability Detection | Determine if vulnerable code paths are reachable |
| CAP-SCA-UNREACH-001 | Unreachable Vulnerability Recognition | Recognize non-reachable vulnerabilities |
| CAP-SCA-EXPLOIT-001 | Exploitability Assessment | Assess if a CVE is actually exploitable in context |
| CAP-SCA-LICENSE-001 | License Risk Detection | Detect problematic license combinations |
| CAP-SCA-LOG4J-001 | Log4Shell Detection | Detect Log4j CVE-2021-44228 |
| CAP-SCA-JACKSON-001 | Jackson Deserialization Detection | Detect Jackson deserialization CVEs |
| CAP-SCA-SNAKEYAML-001 | SnakeYAML Detection | Detect SnakeYAML deserialization CVEs |
| CAP-SCA-COMMONS-001 | Commons Collections Detection | Detect Apache Commons Collections gadget chains |
| CAP-SCA-SPRING-001 | Spring Component CVE Detection | Detect Spring framework CVEs |

### 2.3 DAST Capabilities (CAP-DAST-*)

| Capability ID | Name | Description |
|--------------|------|-------------|
| CAP-DAST-SQLI-001 | Runtime SQL Injection Detection | Detect SQL injection via HTTP requests |
| CAP-DAST-XSS-001 | Runtime XSS Detection | Detect XSS via HTTP requests |
| CAP-DAST-CSRF-001 | Runtime CSRF Detection | Detect missing CSRF tokens |
| CAP-DAST-SSRF-001 | Runtime SSRF Detection | Detect SSRF via HTTP requests |
| CAP-DAST-REDIRECT-001 | Runtime Open Redirect Detection | Detect open redirects via HTTP requests |
| CAP-DAST-TRAVERSAL-001 | Runtime Path Traversal Detection | Detect path traversal via HTTP requests |
| CAP-DAST-UPLOAD-001 | Runtime File Upload Detection | Detect unrestricted file upload via HTTP |
| CAP-DAST-AUTH-001 | Runtime Auth Weakness Detection | Detect authentication weaknesses |
| CAP-DAST-AUTHZ-001 | Runtime AuthZ Weakness Detection | Detect authorization weaknesses |
| CAP-DAST-API-001 | Runtime API Security Detection | Detect API security issues |

### 2.4 Secret Scanning Capabilities (CAP-SECRET-*)

| Capability ID | Name | Description |
|--------------|------|-------------|
| CAP-SECRET-AWS-001 | AWS Key Detection | Detect AWS access/secret keys |
| CAP-SECRET-GITHUB-001 | GitHub Token Detection | Detect GitHub personal access tokens |
| CAP-SECRET-GITLAB-001 | GitLab Token Detection | Detect GitLab tokens |
| CAP-SECRET-SLACK-001 | Slack Token Detection | Detect Slack API tokens |
| CAP-SECRET-AZURE-001 | Azure Credential Detection | Detect Azure service principal credentials |
| CAP-SECRET-GCP-001 | GCP Credential Detection | Detect GCP service account keys |
| CAP-SECRET-JWT-001 | JWT Secret Detection | Detect hardcoded JWT signing secrets |
| CAP-SECRET-DB-001 | Database Password Detection | Detect database connection passwords |
| CAP-SECRET-SSH-001 | SSH Key Detection | Detect embedded SSH private keys |
| CAP-SECRET-CERT-001 | Certificate Detection | Detect embedded certificates/private keys |

### 2.5 Container Security Capabilities (CAP-CONTAINER-*)

| Capability ID | Name | Description |
|--------------|------|-------------|
| CAP-CONTAINER-ROOT-001 | Root User Detection | Detect containers running as root |
| CAP-CONTAINER-PRIVESC-001 | Privilege Escalation Detection | Detect privilege escalation risks |
| CAP-CONTAINER-CAPS-001 | Dangerous Capabilities Detection | Detect dangerous Linux capabilities |
| CAP-CONTAINER-BASE-001 | Outdated Base Image Detection | Detect outdated or vulnerable base images |
| CAP-CONTAINER-SECRET-001 | Exposed Secret Detection | Detect secrets in container images |
| CAP-CONTAINER-RUNTIME-001 | Weak Runtime Config Detection | Detect weak runtime configurations |
| CAP-CONTAINER-SURFACE-001 | Attack Surface Detection | Detect excessive attack surface |
| CAP-CONTAINER-HEALTH-001 | Missing Health Check Detection | Detect missing health checks |
| CAP-CONTAINER-PKG-001 | Package Vulnerability Detection | Detect vulnerable packages in images |
| CAP-CONTAINER-PERMS-001 | Weak File Permission Detection | Detect weak file permissions |

### 2.6 IaC Security Capabilities (CAP-IAC-*)

| Capability ID | Name | Description |
|--------------|------|-------------|
| CAP-IAC-S3PUB-001 | Public Storage Detection | Detect publicly accessible storage buckets |
| CAP-IAC-DBPUB-001 | Public Database Detection | Detect publicly accessible databases |
| CAP-IAC-SG-001 | Weak Security Group Detection | Detect overly permissive security groups |
| CAP-IAC-IAM-001 | Excessive IAM Permission Detection | Detect overly broad IAM policies |
| CAP-IAC-ENCRYPT-001 | Missing Encryption Detection | Detect unencrypted resources |
| CAP-IAC-LOG-001 | Missing Logging Detection | Detect resources without audit logging |
| CAP-IAC-SEG-001 | Weak Segmentation Detection | Detect insufficient network segmentation |
| CAP-IAC-RBAC-001 | Dangerous RBAC Detection | Detect overly permissive RBAC roles |
| CAP-IAC-PRIVPOD-001 | Privileged Container Detection | Detect privileged pods in K8s |
| CAP-IAC-HOSTPATH-001 | HostPath Mount Detection | Detect dangerous hostPath mounts |
| CAP-IAC-SECRET-001 | Insecure Secret Handling Detection | Detect secrets in IaC manifests |

### 2.7 AI Capabilities (CAP-AI-*)

| Capability ID | Name | Description |
|--------------|------|-------------|
| CAP-AI-FIX-001 | AI Fix Generation | Generate correct code fixes for vulnerabilities |
| CAP-AI-REMED-001 | AI Remediation Guidance | Provide actionable remediation guidance |
| CAP-AI-RCA-001 | AI Root Cause Analysis | Accurately identify root cause of vulnerabilities |
| CAP-AI-REACH-001 | AI Reachability Analysis | Determine reachability using AI analysis |
| CAP-AI-PRIO-001 | AI Prioritization | Prioritize findings based on risk and context |
| CAP-AI-RISK-001 | AI Risk Ranking | Rank vulnerabilities by actual risk |
| CAP-AI-SUMMARY-001 | AI Executive Summary | Generate executive-level security summaries |
| CAP-AI-EXPLAIN-001 | AI Code Explanation | Explain vulnerable code patterns |

---

## 3. Capability-to-Benchmark Mapping Strategy

### 3.1 Mapping Rules

1. **Every capability must map to at least one benchmark scenario.**
2. **Every benchmark scenario must map to at least one capability.**
3. **No orphan capabilities** — capabilities without benchmark scenarios are invalid.
4. **No orphan benchmarks** — benchmark scenarios without capability mappings are invalid.
5. **Control pairs share capability mappings** — all four variants (vulnerable, safe, unreachable, framework-protected) map to the same capability set.

### 3.2 Mapping Cardinality

- One capability → Many benchmark scenarios (1:N)
- One benchmark scenario → Many capabilities (N:1)
- Result: Many-to-Many (M:N) relationship

### 3.3 KPI Weight Assignment

Each capability receives a KPI weight based on:
- **Criticality**: How critical is the vulnerability class?
- **Prevalence**: How commonly does this appear in enterprise applications?
- **Impact**: What is the potential business impact?
- **Complexity**: How sophisticated is the detection required?

Weight scale: 0.0 (informational) to 1.0 (critical)

---

## 4. Evaluation Methodology

### 4.1 Per-Capability Scoring

For each capability, calculate:

| Metric | Formula |
|--------|---------|
| Detection Rate | (Detected Scenarios / Total Scenarios) × 100% |
| True Positive Accuracy | (Correct Detections / Total Detections) × 100% |
| Severity Accuracy | (Correct Severity / Total Detected) × 100% |
| Reachability Accuracy | (Correct Reachability / Total Detected) × 100% |

### 4.2 Cross-Capability Aggregation

Weighted average across all capabilities:

```
Overall Score = Σ(Capability Score × KPI Weight) / Σ(KPI Weights)
```

### 4.3 AI Feature Evaluation

AI capabilities are evaluated qualitatively and quantitatively:
- **Fix correctness**: Does the AI-generated fix resolve the vulnerability?
- **Fix compilability**: Does the fix compile without errors?
- **Remediation relevance**: Is the guidance relevant and actionable?
- **Root cause accuracy**: Does the AI correctly identify the root cause?
- **Prioritization alignment**: Does the AI priority match the expected risk?
