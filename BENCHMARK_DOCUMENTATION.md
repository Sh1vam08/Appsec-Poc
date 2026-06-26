# Enterprise AppSec Benchmark Suite (ShopSphere E-Commerce)

## 1. What is this Application?
On the surface, this application appears to be the **ShopSphere E-Commerce Platform Suite**—a premium digital marketplace for hardware, audio solutions, and peripherals. However, under the hood, it is actually the **Enterprise AppSec Benchmark Suite v1.0.0-BENCHMARK**. 

It is an intentionally vulnerable Spring Boot web application designed strictly for evaluating and benchmarking Application Security (AppSec) tools such as SAST (Static Application Security Testing), DAST (Dynamic Application Security Testing), SCA (Software Composition Analysis), and Secret Scanners.

## 2. Functional Logic vs. UI Facades
Because the application's primary goal is to provide vulnerability sinks rather than sell products, much of the user interface consists of facades designed to trigger these vulnerabilities during a web crawl:
- **Search Bar**: Looks like a product search, but directly passes parameters to an SQL Injection vulnerable endpoint.
- **Category Filters (Hardware, Audio, Peripherals)**: They appear to filter products, but actually submit NoSQL Injection payloads to a MongoDB repository.
- **Add to Cart Buttons**: Do not modify any cart state. They are form submissions designed to test Cross-Site Request Forgery (CSRF) protections (secretly attempting to update user emails).
- **Download Product Sheet Links**: Do not serve standard PDFs. They hit an endpoint vulnerable to Path/Directory Traversal, capable of reading arbitrary files like `schema.sql`.
- **Product Reviews**: The review submission form is a sink for Stored Cross-Site Scripting (XSS).
- **Social Share Links (Footer)**: These links act as targets for Open Redirect vulnerabilities.

**What is Functional:** The web server routing, database connections (H2 and MongoDB drivers), file reading mechanisms, and internal logic to execute the vulnerabilities are fully functional.

## 3. Embedded Vulnerabilities & Areas
The application contains hundreds of benchmark scenarios (indicated by comments like `// BENCH-SAST-XXX` or `BENCH-DAST-XXX`). Vulnerabilities are generally implemented in clusters:
- **Vulnerable Variant**: Direct, easily exploitable implementation (True Positive expected).
- **Safe Variant**: Mitigated or properly parameterized implementation (False Positive expected if flagged).
- **Unreachable Variant**: Vulnerable logic that is unreachable via execution flow (to test SAST dead-code analysis).

### Key Vulnerability Areas (DAST & SAST):
- **SQL Injection (SQLi)**: Triggered via the `GET /api/v1/products/search` endpoint.
- **NoSQL Injection**: Triggered via the `GET /api/v1/products/filter` endpoint.
- **Path Traversal**: Triggered via the `GET /api/v1/orders/invoice/download` endpoint.
- **Cross-Site Request Forgery (CSRF)**: Triggered via the `POST /api/v1/cart/items` endpoint.
- **Stored XSS**: Triggered via the `POST /reviews/product` endpoint.
- **Open Redirects**: Triggered via the `GET /api/v1/share/redirect` endpoint.

### Other Scanners (SCA & Secrets):
- **Software Composition Analysis (SCA)**: Multiple outdated and vulnerable dependencies are intentionally included in the `pom.xml` (e.g., old versions of Log4j, Spring, etc.).
- **Secret Scanning**: Hardcoded API keys, tokens, and credentials (e.g., AWS, Azure, GitHub, GitLab, Slack) are embedded inside utility classes located in `src/main/java/com/shopsphere/util/`.

## 4. How Scans Will Be Performed
- **SAST (Static Analysis)**: The scanner will analyze the source code (primarily `src/main/java`) to detect data flow from sources (controllers) to sinks (database executions, file reads, etc.) without requiring compilation or running the app.
- **DAST (Dynamic Analysis)**: The application is packaged into a JAR and executed locally (e.g., `java -jar target/appsec-benchmark-1.0.0-BENCHMARK.jar`). The DAST tool is given the entry URL (`http://localhost:8080`) and will crawl the UI elements (forms, links, inputs) and inject payloads into parameters and headers.
- **SCA & Secret Scanning**: Scanners will parse the `pom.xml` and statically regex-search the codebase for entropy and token patterns.

## 5. Expected Results
The scanners are expected to find the `Vulnerable` variants of the scenarios while ignoring the `Safe` and `Unreachable` variants.
- **True Positives (TP)**: The scanner successfully identifies a known vulnerability (e.g., it flags the `searchVulnerable` NoSQL endpoint).
- **False Positives (FP)**: The scanner incorrectly flags a safe implementation as vulnerable (e.g., it flags the parameterized `searchSafe` NoSQL endpoint).
- **False Negatives (FN)**: The scanner completely misses a vulnerable endpoint.

## 6. KPI Calculation
The evaluation of the AppSec tools will be measured using standard classification metrics (KPIs) based on the scenarios detected:

1. **Precision (Accuracy of alerts)**: 
   `Precision = TP / (TP + FP)`
   *High precision means the tool produces very little noise or false alarms.*

2. **Recall (Detection coverage)**: 
   `Recall = TP / (TP + FN)`
   *High recall means the tool successfully identifies the vast majority of actual vulnerabilities.*

3. **F1-Score (Balanced Metric)**: 
   `F1 = 2 * ((Precision * Recall) / (Precision + Recall))`
   *The harmonic mean of precision and recall provides a single score to evaluate the overall effectiveness of the scanner.*

## 7. Component-by-Component Application Breakdown
The codebase is structured into modules under `src/main/java/com/shopsphere/`. Below is a detailed explanation of each module, outlining its apparent "E-Commerce Purpose" and its actual "AppSec Vulnerability Purpose."

### `auth`
- **E-Commerce Purpose:** Handles user login, authentication, and order access control.
- **AppSec Purpose:** Tests tools for identifying Authentication Bypasses, Weak Password Hashing, LDAP Injection, and Broken Access Control (BOLA/IDOR).

### `cart`
- **E-Commerce Purpose:** Manages user shopping carts and checkout flows.
- **AppSec Purpose:** Acts as a primary sink for Cross-Site Request Forgery (CSRF). "Add to Cart" interactions are secretly engineered to modify user state (like changing an email) without proper anti-CSRF tokens.

### `catalog`
- **E-Commerce Purpose:** Manages product listings, search bars, category filters, promo codes, and inventory imports.
- **AppSec Purpose:** This is the most vulnerability-dense module:
  - **Search:** SQL Injection sinks.
  - **Filters:** NoSQL Injection sinks (MongoDB).
  - **Promo Codes:** XML External Entity (XXE) injection sinks via XML imports.
  - **Inventory Imports:** OS Command Injection sinks.

### `common`
- **E-Commerce Purpose:** Manages shared logic like OAuth redirects, social sharing links, session restores, and vendor webhooks.
- **AppSec Purpose:** 
  - **Redirects:** Open Redirect vulnerabilities (allowing phishing attacks).
  - **Webhooks:** Server-Side Request Forgery (SSRF) vulnerabilities.
  - **Session Restore:** Insecure Deserialization of Java objects.

### `config`
- **E-Commerce Purpose:** Sets up the Spring Boot server, database drivers, and web routing.
- **AppSec Purpose:** Contains intentional Security Misconfigurations (e.g., globally disabling CSRF, overly permissive CORS policies, and exposing sensitive Actuator endpoints).

### `order`
- **E-Commerce Purpose:** Handles the final checkout step and invoice generation/download.
- **AppSec Purpose:** The invoice download feature is a classic Path/Directory Traversal sink, allowing tools to detect if a user can escape the webroot and download arbitrary system files (e.g., `../../etc/passwd`).

### `payment`
- **E-Commerce Purpose:** Processes credit cards and payment gateway configurations.
- **AppSec Purpose:** Tests for Cryptographic Failures. It intentionally uses broken/deprecated algorithms (like MD5, DES, or ECB mode) and insecure random number generators for encrypting mock payment data.

### `profile`
- **E-Commerce Purpose:** Allows users to view and update their shipping addresses and profiles.
- **AppSec Purpose:** Sinks for Insecure Direct Object Reference (IDOR). Tools must detect if changing a `user_id` parameter allows access to another user's profile.

### `reporting`
- **E-Commerce Purpose:** Admin dashboard for analytics and plugin management.
- **AppSec Purpose:** Tests for Unsafe Reflection and SpEL (Spring Expression Language) Injection via administrative plugin execution.

### `review`
- **E-Commerce Purpose:** Lets users leave feedback and product reviews.
- **AppSec Purpose:** The primary sink for Cross-Site Scripting (XSS). Contains variants for Stored XSS (saved in the database) and Reflected XSS (bounced straight back in the response).

### `support`
- **E-Commerce Purpose:** Customer support asset downloads and profile image uploads.
- **AppSec Purpose:** Tests Unrestricted File Upload vulnerabilities (e.g., allowing a user to upload a malicious `.jsp` or `.svg` file instead of a valid `.png`).

### `system`
- **E-Commerce Purpose:** Provides network diagnostics (like pinging a server to check connectivity).
- **AppSec Purpose:** Direct sink for OS Command Injection (appending `; rm -rf /` to the ping command).

### `util`
- **E-Commerce Purpose:** Helper classes for integrating with Azure, AWS, GitHub, and Slack.
- **AppSec Purpose:** Contains absolutely zero runtime logic. It exists purely as a goldmine for Secret Scanning tools, containing hardcoded (but revoked/dummy) API Keys, SSH Keys, and OAuth Tokens.
