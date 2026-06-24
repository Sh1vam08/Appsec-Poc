# ShopSphere - E-Commerce and Digital Services Platform

## Overview
**ShopSphere** is a purpose-built, runnable Spring Boot 3.x web application that models a modern online marketplace and digital services platform, designed to act as an evaluation corpus for application security scanning platforms.

It contains benchmark scenarios targeting:
- **SAST** (Static Application Security Testing)
- **SCA** (Software Composition Analysis)
- **DAST** (Dynamic Application Security Testing)
- **Secrets** (Secret Scanning)
- **Container Security** (Docker)
- **IaC Security** (Infrastructure as Code)

> [!WARNING]
> **THIS IS AN INTENTIONALLY VULNERABLE APPLICATION.**
> It contains real security vulnerabilities and exploits. Do not deploy to production or expose it to public network interfaces. Run only in isolated, sandboxed environments.

---

## Prerequisites
- **Java SE Development Kit (JDK) 17**
- **Apache Maven 3.9.x**
- *(Optional)* **Docker & Docker Compose**

---

## How to Build
To compile the source code and build the executable JAR:
```bash
mvn clean package
```

To run unit and integration tests (validating the base framework context):
```bash
mvn test
```

---

## How to Run Locally

### Running via Maven
To run the Spring Boot application locally:
```bash
mvn spring-boot:run
```

### Running the JAR File
Once compiled, you can run the JAR directly:
```bash
java -jar target/appsec-benchmark-1.0.0-BENCHMARK.jar
```

---

## How to Run via Docker

You can build and spin up the containerized application using Docker Compose:
```bash
docker-compose up --build
```
This builds the multi-stage container and exposes the app on port `8080`.

---

## Key Endpoints

Once the application starts, the following endpoints are available:

| Service | Endpoint URL | Description |
|---------|--------------|-------------|
| **Actuator Health** | [http://localhost:8080/actuator/health](http://localhost:8080/actuator/health) | System health status check |
| **Actuator Info** | [http://localhost:8080/actuator/info](http://localhost:8080/actuator/info) | Info endpoint |
| **Swagger UI** | [http://localhost:8080/swagger-ui/index.html](http://localhost:8080/swagger-ui/index.html) | OpenAPI interactive documentation |
| **API Docs** | [http://localhost:8080/v3/api-docs](http://localhost:8080/v3/api-docs) | Raw OpenAPI v3 JSON spec |
| **H2 Console** | [http://localhost:8080/h2-console](http://localhost:8080/h2-console) | In-memory DB visual administrator |

### Database Console Configuration
When logging into the **H2 Console**, use these settings:
- **Driver Class:** `org.h2.Driver`
- **JDBC URL:** `jdbc:h2:mem:benchmarkdb`
- **User Name:** `sa`
- **Password:** *(leave blank)*
