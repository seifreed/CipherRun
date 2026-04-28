# CipherRun — Copilot Instructions

CipherRun is a fast, modular TLS/SSL security scanner written in Rust. It operates as a CLI tool and optionally as a REST API server.

## Build & Test Commands

```bash
# Build
cargo build
cargo build --release

# Run all tests
cargo test

# Run a single test by name
cargo test test_connection_timeout_error
cargo test --test api_auth_tests test_auth_valid_admin_key_returns_200

# Run tests in a specific integration test file
cargo test --test api_auth_tests

# Format
cargo fmt

# Lint
cargo clippy -- -D warnings

# Run architecture boundary tests
cargo test --test architecture_guards

# Formal verification (requires `cargo kani` installed)
cargo kani

# Docker-based environment
make quickstart          # build + run
make test-domain DOMAIN=example.com
make shell               # enter container
```

Logging is controlled via `RUST_LOG` (e.g. `RUST_LOG=debug cargo run -- example.com`).

## Architecture

### Layer overview (Hexagonal / Clean Architecture)

| Layer | Directories | Role |
|-------|-------------|------|
| **Adapters** | `src/cli`, `src/api`, `src/output` | I/O, transport, presentation — map external models to application models |
| **Application** | `src/application` | Use-case orchestration; defines port traits (`ports/`) |
| **Core/Domain** | `src/scanner`, `src/compliance`, `src/vulnerabilities`, `src/ciphers`, etc. | Pure TLS/security logic |
| **Infrastructure** | `src/db`, `src/external` | Implements ports (database repos, external HTTP clients) |

**Enforced boundary rules** (verified by `cargo test --test architecture_guards`):
- `src/policy` and `src/db` must not reference `crate::scanner::ScanResults` directly; use the `PersistedScan` DTO from `src/application/persistence/`.
- Scanner core must not import `crate::Args` or API models.
- Application layer must not call `process::exit` or write directly to stdout/stderr.
- `src/db/history.rs` must not contain raw SQL; it's a thin wrapper over repositories.

### Entry point → command routing

`main.rs` parses `Args` (clap), then calls `CommandRouter::route(args)` which returns a boxed `Command` trait object. Each command lives in `src/commands/` (e.g. `ScanCommand`, `ApiServerCommand`, `MassScanCommand`, `MonitorCommand`). All commands implement `Command::execute() -> Result<CommandExit>`.

### Domain layer (`src/application/`)

`ScanRequest` is the central domain object that `Args::to_scan_request()` produces. It flows through the entire scan pipeline. The `ports/` sub-module defines repository/service traits (e.g. `ScanResultsStore`, `ScanHistoryPort`) that the database and API layers implement.

### Scanner engine (`src/scanner/`)

Phase-based orchestration: `Scanner` (in `service.rs`) delegates to phases in `phases/`. Multi-IP scanning is in `multi_ip/` with result aggregation in `aggregation/`. Progress reporting uses dependency injection (`ScanProgressReporter` trait with `TerminalProgressReporter` / `SilentProgressReporter`).

### API server (`src/api/`)

Axum 0.7 REST API. Sub-modules: `routes/`, `models/`, `middleware/`, `presenters/`, `adapters/`, `jobs/`, `ws/` (WebSocket progress), `state.rs`, `openapi.rs` (utoipa). API key auth is in middleware.

### CLI arguments (`src/cli/`)

`Args` in `src/cli/mod.rs` composes ~15 domain-specific sub-structs (e.g. `ScanArgs`, `NetworkArgs`, `ConnectionArgs`) using clap's `#[command(flatten)]`. Add new flags to the appropriate sub-struct, not directly to `Args`.

### Database (`src/db/`)

SQLx with both PostgreSQL and SQLite support. Config loaded from a TOML file (`database.toml`). Migrations are in `migrations/` and follow the naming pattern `YYYYMMDD_NNN_<description>.sql`. Run `cipherrun --db-config-example database.toml` to generate an example config.

### Output (`src/output/`)

Formatters for terminal (colored tables via `scanner_formatter/`), HTML (Handlebars templates), XML, CSV, and JSON. Multi-IP terminal output is separate (`multi_ip_terminal.rs`).

## Key Conventions

### Error handling

The canonical error type is `TlsError` (in `src/error.rs`, derived with `thiserror`). The crate-level result alias is `cipherrun::Result<T>`. Use the provided macros instead of constructing variants manually:

```rust
tls_bail!("something went wrong: {}", reason);  // early return with TlsError::Other
cert_error!(Expired { expiry_date: "2024-01-01".to_string() }) // construct CertificateValidationError
```

`anyhow::Result` is **deprecated** (`AnyhowResult<T>`). New code must use `cipherrun::Result<T>`. Existing `anyhow` usage is being migrated.

### Tests

- **Unit tests** live in `#[cfg(test)]` modules inside source files.
- **Integration tests** live in `tests/` as separate files.
- All integration tests share helpers via `mod common` (`tests/common/mod.rs`), which provides `common::api::test_api_router()` and `common::sqlite::unique_sqlite_db_path(...)`.
- Test assertions use `.expect("test assertion should succeed")` (not `.unwrap()`) to give meaningful failure messages.
- Async tests use `#[tokio::test]`.

### Module structure

Each module exposes its public API through `mod.rs` re-exports. Internal sub-modules are private by default. When adding a new top-level module, register it in `src/lib.rs`.

### `ScanRequest` as the data transfer object

`Args` → `ScanRequest` is the boundary between CLI parsing and business logic. The API server also constructs `ScanRequest` from JSON. Keep scan logic dependent on `ScanRequest`, not on `Args`.

### Database migrations

Name new migration files as `YYYYMMDD_NNN_<snake_case_description>.sql` and place them in `migrations/`. SQLx runs them automatically at startup when the database feature is enabled.

### Kani proofs

Formal verification harnesses live in `src/proofs/` and are only compiled under `#[cfg(kani)]`. Do not add `#[cfg(kani)]` guards anywhere else in the codebase; use `pub mod proofs` in `lib.rs` gated on the cfg.
