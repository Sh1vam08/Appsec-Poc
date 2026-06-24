# =========================================================================
# Enterprise AppSec Benchmark Suite
# Phase 2: Core Spring Boot Skeleton Dockerfile
#
# Multi-stage build: compiles the app and packages it into a minimal JRE.
# Runs the containerized application as a non-root user.
# =========================================================================

# Stage 1: Build stage using Maven and JDK 17
FROM maven:3.9.6-eclipse-temurin-17 AS builder
WORKDIR /build

# Copy the pom.xml and cache dependencies
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy the source code and build the JAR
COPY src ./src
RUN mvn clean package -DskipTests -B

# Stage 2: Runtime stage using minimal Eclipse Temurin JRE 17
FROM eclipse-temurin:17-jre
WORKDIR /app

# Expose standard application port
EXPOSE 8080

# BENCH-CONT-001: Expose unnecessary sensitive port (Misconfiguration)
EXPOSE 22

# BENCH-CONT-002 / BENCH-SEC-002: Hardcoded secret in container environment variable
ENV STRIPE_API_KEY="sk_live_51JvT9Z2eZvKYlo2CUz..."
ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Copy the packaged jar from the builder stage
COPY --from=builder /build/target/appsec-benchmark-1.0.0-BENCHMARK.jar appsec-benchmark.jar

# BENCH-CONT-003: Running as root (Intentional removal of non-root user creation)
# The application runs as the default root user instead of a restricted user.

# Run the Spring Boot application
ENTRYPOINT ["java", "-jar", "appsec-benchmark.jar"]
