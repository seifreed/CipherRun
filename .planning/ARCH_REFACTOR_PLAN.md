# Architecture Refactor Plan

## Goal

Move CipherRun from a modular-but-coupled structure toward a cleaner architecture where:

- CLI and API are adapters.
- Application owns orchestration.
- Scanner no longer depends on `crate::Args`.
- Persistence, compliance, and policy consume stable application/domain views.

## Constraints

- No mocks in production refactors or verification.
- Preserve current behavior while changing dependency direction incrementally.
- Avoid reverting unrelated local changes already present in the worktree.

## Phase 1: Separate Scan Use Case Input

### Scope

- Introduce internal `application::ScanRequest`.
- Remove direct `crate::Args` dependency from `Scanner` and scanner phases.
- Add mappers:
  - `Args -> ScanRequest`
  - `API ScanOptions -> ScanRequest`

### Deliverables

- `src/application/scan_request.rs`
- Scanner constructors and contexts updated to use `ScanRequest`
- CLI/API integrations mapped through `ScanRequest`

### Acceptance Criteria

- `Scanner` stores `ScanRequest`, not `Args`
- Scanner phases use `ScanRequest`
- CLI/API create `ScanRequest` before invoking scanner

## Phase 2: Extract Application Use Cases

### Scope

- Introduce `application::use_cases` with:
  - `RunScan`
  - `EvaluateCompliance`
  - `EvaluatePolicy`
  - `StoreScanResults`
- Reduce `ScanCommand` to a thin adapter.

### Deliverables

- New use case modules
- `ScanCommand` delegating orchestration

### Acceptance Criteria

- Main orchestration no longer lives in `src/commands/scan.rs`
- CLI remains responsible only for input mapping and rendering

## Phase 3: Decouple Persistence

### Scope

- Stop passing `scanner::ScanResults` directly into DB.
- Introduce persistence-facing DTOs or application records.
- Put storage behind application ports.

### Deliverables

- Application port for scan storage
- Mapper from scan result view to persistence records

### Acceptance Criteria

- `src/db` no longer depends on scanner internals

## Phase 4: Decouple Compliance and Policy

### Scope

- Introduce a stable evaluation view such as `SecurityAssessment`.
- Make policy and compliance depend on that view, not scanner result internals.

### Deliverables

- Evaluation-facing DTO/view
- Policy/compliance integration migrated

### Acceptance Criteria

- Policy and compliance no longer import `scanner::ScanResults`

## Phase 5: Break Down Large Files

### Scope

- Split `src/output/scanner_formatter.rs`
- Split `src/scanner/mod.rs`
- Split `src/vulnerabilities/tester.rs`

### Acceptance Criteria

- Clear responsibility boundaries
- Smaller units with focused tests

## Phase 6: Remove Internal Side Effects

### Scope

- Move `println!`, `eprintln!`, and `std::process::exit` to adapters.
- Return typed outputs/statuses from application use cases.

### Acceptance Criteria

- Application returns data, adapters decide how to present and exit

## Phase 7: Unify Validation

### Scope

- Centralize target, timeout, port, and flag validation.
- Keep one source of truth for scan input rules.

## Phase 8: Clean Test Duplication

### Scope

- Introduce builders/fixtures for API and command tests.
- Normalize file naming and separate unit vs integration suites.

## Phase 9: Document Architecture Rules

### Scope

- Document allowed dependency direction.
- Add lightweight CI or convention checks.

## Execution Order

1. Remove `Args` from scanner input path.
2. Extract application use cases.
3. Decouple DB from scanner result internals.
4. Decouple compliance/policy from scanner result internals.
5. Split large files.
6. Clean tests and codify rules.

## Current Execution Slice

This change set targets:

- Phase 1 fully
- Phase 2 skeleton (`application::use_cases`)
