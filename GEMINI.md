# CipherRun Development Guide

This document provides essential context and instructions for AI agents working on the CipherRun codebase.

## Project Overview

**CipherRun** is a high-performance, modular TLS/SSL security scanner and compliance engine built in Rust. It provides comprehensive analysis of TLS configurations, certificate health, and vulnerability status.

- **Primary Language:** Rust (Edition 2024)
- **Runtime:** Tokio (Async/Await)
- **Architecture:** Hexagonal / Clean Architecture (Adapters, Application, Core, Infrastructure)
- **Key Capabilities:**
    - Protocol & Cipher enumeration (SSLv2 to TLS 1.3)
    - Vulnerability scanning (Heartbleed, ROBOT, POODLE, etc.)
    - Compliance auditing (PCI-DSS, NIST, SOC2, HIPAA, etc.)
    - TLS Fingerprinting (JA3, JA3S, JARM)
    - Certificate Transparency (CT) log monitoring
    - API & CLI interfaces

## Core Technologies

- **Networking:** `tokio`, `rustls`, `openssl`, `hickory-resolver`
- **Web API:** `axum`, `tower-http`, `utoipa` (OpenAPI)
- **Database:** `sqlx` (PostgreSQL and SQLite support)
- **CLI:** `clap` (v4 with derive)
- **Serialization:** `serde`, `serde_json`, `serde_yaml`
- **Error Handling:** `thiserror` (structured errors in `src/error.rs`)

## Architectural Principles

Strict adherence to the layers defined in `ARCHITECTURE.md` is mandatory.

1.  **Adapters (`src/cli`, `src/api`, `src/output`):** Handle I/O, transport, and presentation. They map external models to application models.
2.  **Application (`src/application`):** Orchestrates use cases and defines ports (traits). It should not depend on infrastructure details.
3.  **Core/Domain (`src/scanner`, `src/compliance`, etc.):** Pure logic for scanning and security analysis.
4.  **Infrastructure (`src/db`, `src/external`):** Implements ports defined by the application layer (e.g., database repositories).

### Dependency Rules
- **No Circular Dependencies:** Layers must follow a strict downward dependency flow.
- **Scanner Core Independence:** The scanner core must not depend on CLI arguments (`crate::Args`) or API models.
- **Error Handling:** Use `cipherrun::Result<T>` and the `TlsError` enum for all new logic. Avoid generic `anyhow` in core modules.

## Development Workflow

### Key Commands

- **Build:** `cargo build`
- **Test:** `cargo test`
- **Architectural Guards:** `cargo test --test architecture_guards` (Ensures layer boundaries are respected)
- **Lint:** `cargo clippy`
- **Format:** `cargo fmt`
- **Database Migrations:** `sqlx migrate run` (Requires `DATABASE_URL`)

### Testing Strategy

- **Integration Tests:** Located in `tests/`. Use these for verifying E2E flows (CLI, API, Scanner).
- **Unit Tests:** Located in the same file as the code (`mod tests`).
- **Architecture Tests:** `tests/architecture_guards.rs` validates that new changes don't break the intended layer separation.

## Project Structure

- `src/api/`: Axum-based REST API and WebSocket handlers.
- `src/application/`: Use cases, ports, and internal DTOs.
- `src/certificates/`: Logic for X.509 parsing, validation, and trust stores.
- `src/ciphers/`: Cipher suite definitions and testing logic.
- `src/compliance/`: Framework-based security requirement evaluators.
- `src/scanner/`: The central async scanning engine.
- `src/vulnerabilities/`: Implementations of specific TLS vulnerability checks.
- `data/`: Static signature databases and compliance definitions (YAML).

## Contribution Guidelines

- **Surgical Updates:** When fixing bugs or adding features, maintain the existing architectural seams.
- **Documentation:** Update `ARCHITECTURE.md` if introducing new architectural patterns or layer boundaries.
- **Verification:** Always run the full test suite, including `architecture_guards`, before finalizing changes.
