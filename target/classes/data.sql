-- Seed Data for Enterprise AppSec Benchmark Suite
-- Phase 2: Core Spring Boot Skeleton Baseline (Clean, Safe)

-- Passwords are BCrypt hashes of "password" ($2a$10$dXJ3ADWyyTXuJRd8G.jZ5O2H.A66d0q82XgD/U.mhzv61mBvS2Jk2)
-- Seed Data for Enterprise AppSec Benchmark Suite
-- Phase 2: Core Spring Boot Skeleton Baseline (Clean, Safe)

-- Passwords are BCrypt hashes of "password" ($2a$10$dXJ3ADWyyTXuJRd8G.jZ5O2H.A66d0q82XgD/U.mhzv61mBvS2Jk2)
INSERT INTO users (id, username, password, email, role, created_at) VALUES 
(1, 'admin', '$2a$10$dXJ3ADWyyTXuJRd8G.jZ5O2H.A66d0q82XgD/U.mhzv61mBvS2Jk2', 'admin@benchmark.local', 'ADMIN', CURRENT_TIMESTAMP),
(2, 'user', '$2a$10$dXJ3ADWyyTXuJRd8G.jZ5O2H.A66d0q82XgD/U.mhzv61mBvS2Jk2', 'user@benchmark.local', 'USER', CURRENT_TIMESTAMP);

INSERT INTO products (id, name, description, price, category, created_at) VALUES 
(1, 'Secure Scanner A', 'Enterprise-grade static analysis tool.', 15000.00, 'Security', CURRENT_TIMESTAMP),
(2, 'Defensive Shield B', 'Next-generation web application firewall.', 25000.00, 'Security', CURRENT_TIMESTAMP),
(3, 'Cloud Watcher C', 'Container and IaC configuration auditor.', 9800.00, 'Cloud', CURRENT_TIMESTAMP);

INSERT INTO vulnerability_reports (id, title, description, severity, status, reporter_id, created_at) VALUES 
(101, 'SQL Injection in Search', 'Found SQL injection vulnerability in user search endpoint.', 'HIGH', 'OPEN', 2, CURRENT_TIMESTAMP),
(102, 'Outdated Log4j', 'Dependency check reported outdated Log4j library version.', 'CRITICAL', 'RESOLVED', 1, CURRENT_TIMESTAMP);

INSERT INTO sensitive_users (id, username, email, ssn, credit_card) VALUES
(1, 'jane_doe', 'jane@benchmark.local', '999-12-3456', '1111-2222-3333-4444'),
(2, 'john_doe', 'john@benchmark.local', '999-98-7654', '5555-6666-7777-8888');

ALTER TABLE vulnerability_reports ALTER COLUMN id RESTART WITH 100;
