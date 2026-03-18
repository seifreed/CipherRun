# Architecture Guide

This document defines the architectural rules for CipherRun as it exists today and the direction for future refactors.

## Goals

- Keep scanning, policy, compliance, and persistence logic reusable from both CLI and API.
- Keep transport concerns at the edges.
- Keep infrastructure details out of application flow where practical.
- Prefer explicit mapping between layers over passing transport or database models through the system.

## Current Layer Model

CipherRun is not a strict Clean Architecture project yet, but it now has a usable layer split:

### 1. Adapters

These modules receive input, invoke application services, and render or serialize output.

- `src/cli`
- `src/commands`
- `src/api/routes`
- `src/api/presenters`
- `src/api/adapters`
- `src/api/ws`
- `src/output`

Responsibilities:

- Parse CLI flags, HTTP requests, and WebSocket messages.
- Map external inputs into application types such as `ScanRequest`.
- Reuse adapter-side helpers for transport-specific parsing and presentation, such as shared HTTP target parsing and response presenters.
- Reuse API adapter/composition helpers when handlers would otherwise repeat service wiring or state extraction.
- Reuse API-side query mappers when routes start repeating request-to-application mapping logic.
- Call application use cases.
- Build adapter-side output/export plans when presentation concerns differ by transport.
- Keep CLI presenters split between TLS rendering, post-processing, artifact export, and post-scan notices when that flow grows.
- Keep CLI presenters/exporters driven by `ScanCliView` intent where possible, not by repeated raw `ScanResults` checks.
- Split large CLI presenters physically once internal seams stabilize, as with `scan_results_presenter/{primary,feature,fingerprint}`.
- Render terminal output, JSON responses, files, and exit codes.
- Keep filesystem/path handling for file-backed HTTP routes in shared route-local helper modules when the handlers start growing.

### 2. Application

These modules orchestrate use cases and define stable internal contracts.

- `src/application`
- `src/application/use_cases`

Key internal contracts already in use:

- `ScanRequest`
- `ScanAssessment`
- `CertificateFilters`
- `CertificateInventoryPort`
- `ScanHistoryPort`
- `PersistedScan`
- `ScanExecutionReport`
- `ScanCliView`
- `ScanPrimaryTlsView`
- `ScanFeatureView`
- `ScanFingerprintView`
- `ScanPostView`
- `ScanExportView`
- `ScanNoticeView`
- `ScanResultsStore`
- parsed input types such as `HostPortInput`

Responsibilities:

- Coordinate scanning, compliance, policy evaluation, and persistence.
- Validate application-level input rules.
- Map between scanner output and stable views used by other layers.
- Define ports such as `ScanResultsStore`, `ScanResultsStoreFactory`, and read-side query ports like `CertificateInventoryPort` and `ScanHistoryPort`.

### 3. Core Services and Domain Logic

These modules implement the main capabilities of the product.

- `src/scanner`
- `src/compliance`
- `src/policy`
- `src/rating`
- `src/protocols`
- `src/ciphers`
- `src/certificates`
- `src/fingerprint`
- `src/http`
- `src/starttls`
- `src/vulnerabilities`
- `src/monitor`
- `src/security`

Responsibilities:

- Execute TLS and certificate analysis.
- Evaluate compliance and policy rules.
- Produce scan results and security assessments.

### 4. Infrastructure

These modules talk to external systems or provide implementation details.

- `src/db`
- `src/db/certificate_inventory`
- `src/db/storage`
- `src/db/history`
- `src/db/scan_history`
- `src/db/repositories`
- `src/external`
- parts of `src/ct_logs`
- filesystem or network integrations elsewhere in the tree

Responsibilities:

- Implement repository and storage concerns.
- Manage SQL pools, migrations, and persistence records.
- Integrate with third-party systems.
- Own config-backed store factories and concrete storage opening.
- Keep low-level batch storage helpers in infrastructure modules instead of concentrating them in `db/mod.rs`.
- Keep certificate inventory queries and backend-specific SQL in infrastructure instead of inside API routes.
- Keep scan history queries and backend-specific SQL in infrastructure instead of inside API routes.
- Prefer explicit infrastructure services such as `CertificateInventoryService` when adapters need read-side queries.
- Prefer explicit infrastructure services such as `ScanHistoryService` when adapters need read-side queries.
- Keep read-side contracts such as `CertificateInventoryPort` and `ScanHistoryPort` in `application`, with infrastructure implementing them.
- Split storage helpers by domain once the file becomes a hotspot again.
- Keep `src/db/storage/mod.rs` as a tiny module façade that only wires domain-specific storage helpers.
- When `src/db/storage/certificates` grows, keep it split by lookup, insert, and link responsibilities instead of collapsing back to one file.

## Dependency Rules

These are the rules contributors should follow.

### Allowed

- `cli`, `commands`, and `api/*` may depend on `application`.
- `application` may depend on `scanner`, `policy`, `compliance`, `rating`, and stable repository traits or persistence DTOs.
- `infrastructure` may depend on `application` contracts and `db` models required for storage.
- `output` may depend on application results or scanner result views for presentation.

### Not Allowed

- `scanner` must not depend on `crate::Args`, Axum request models, or CLI-only types.
- `policy` and `compliance` must not depend directly on `scanner::ScanResults`; they should consume `ScanAssessment` or another stable application view.
- `db` must not depend directly on scanner orchestration types; persistence should go through `PersistedScan` or equivalent application DTOs.
- `application` must not print to stdout/stderr or call `std::process::exit`.
- `domain/core` code must not depend on `clap`, `axum`, `sqlx`, or terminal rendering concerns.

## Mapping Rules

Cross-layer mapping should happen at explicit seams:

- `Args -> ScanRequest`
- `Args -> CertificateFilters`
- API `ScanOptions -> ScanRequest`
- `ScanResults -> ScanAssessment`
- `ScanResults -> PersistedScan`
- application results -> API response models
- shared HTTP target input -> `ScanRequest`
- application results -> terminal formatter input
- `ScanExecutionReport -> ScanCliView`
- `CertificateInventoryPort -> CertificateInventoryService`
- `ScanHistoryPort -> ScanHistoryService`
- scan queue/job state -> API response presenters
- history query results -> API response presenters
- history query requests -> `ScanHistoryPort` -> `ScanHistoryService` -> API response presenters
- certificate inventory rows -> API response presenters
- certificate inventory requests -> `CertificateInventoryPort` -> `CertificateInventoryService` -> API response presenters
- certificate inventory route wiring -> API adapter/composition helper -> `CertificateInventoryService`
- history route wiring -> API adapter/composition helper -> `ScanHistoryService`
- scan execution report -> `ScanCliView` -> specialized scan presenters (`results`, `post`, `export`, `notice`)
- `ScanCliView` should expose render/export intent such as TLS presence, multi-IP export data, and post-scan notices instead of forcing raw result checks in CLI presenters
- `ScanCliView` should expose grouped render intent such as `primary TLS`, `feature`, and `fingerprint/summary` sections instead of forcing presenters to reconstruct those decisions from raw results.
- `ScanCliView` should also expose explicit subview render intent such as `should_render_primary_tls_view`, `should_render_feature_view`, and `should_render_fingerprint_view` once results presenters stop combining grouped section intent with local subview checks.
- `ScanCliView` should also expose explicit detailed-results intent once results presenters stop locally negating summary-only behavior before deciding which rendering path to take.
- `ScanCliView` should also expose explicit summary-only render intent once results presenters stop locally negating detailed-results behavior before deciding which rendering path to take.
- `ScanCliView` should also expose explicit top-level results-render intent once the outer scan presenter stops invoking the results presenter unconditionally.
- `ScanCliView` should also expose explicit results-summary intent once the results presenter stops deciding locally when the final summary block should render.
- `ScanCliView` should also expose high-level export intent such as whether a plan is worth building and whether multi-IP JSON export is meaningful.
- `ScanCliView` should expose focused result subviews such as `ScanPrimaryTlsView`, `ScanFeatureView`, and `ScanFingerprintView` once command-side results presenters no longer need the whole CLI view contract.
- `ScanCliView` should expose focused subviews such as `ScanPostView` once command-side post-processing presenters no longer need the broader post-processing contract.
- `ScanCliView` should expose focused subviews such as `ScanExportView` once command-side exporters no longer need the whole CLI view contract.
- `ScanCliView` should expose focused subviews such as `ScanNoticeView` once command-side notice rendering no longer needs the whole CLI view contract.
- `ScanCliView` should expose explicit post-processing render intent plus artifact-skipping, artifact-handling, and artifact-notice intent once the presenter stops deciding locally when post-processing failures should block exports and notices.
- `ScanCliView` should also expose explicit artifact-notice gating intent when the presenter would otherwise combine broad notice intent with local `Option` checks around artifact outcomes.
- `ScanCliView` should also expose explicit post-scan notice gating intent when the presenter would otherwise recompose top-level notice rendering from local artifact presence checks.
- `ScanCliView` should also expose explicit post-scan export-spacing gating intent when the presenter would otherwise combine raw exporter outcomes with notice-view checks locally.
- `ScanCliView` should also expose notice-ready stored-scan intent for post-scan notice flows when the presenter would otherwise combine artifact gating with raw notice-view storage checks locally.
- `ScanCliView` should also expose artifact-notice-ready stored-scan and export-spacing intent when the presenter would otherwise thread hard-coded artifact-presence flags into post-scan notice checks.
- Once artifacts and notices are driven by focused CLI views, `scan_presenter` should not keep threading the broader `ScanPostProcessingView` contract into artifact handling.
- `ScanCliView` should expose explicit export-attempt intent when the presenter would otherwise decide locally whether artifact handling plus available result data justify invoking the exporter.
- `ScanExportView` should expose explicit exportable-results and multi-IP export intent once exporters stop inferring those decisions from the broader CLI view.
- `ScanPostView` should expose aggregated failure intent, explicit failure-exit intent, and explicit policy-failure notice intent once post-processing presenters stop recomputing failure behavior locally.
- `ScanNoticeView` should expose explicit notice-rendering intent, stored-scan intent, storage-notice intent, and export-spacing intent once notice rendering no longer needs to infer it ad hoc from raw option checks, exporter booleans, or redundant stored-scan IDs threaded through presenter outcomes.
- `ScanNoticeView` should also expose notice-ready stored-scan data once the presenter stops composing storage-intent checks with raw optional IDs locally.
- `ScanPostProcessingView` should expose compliance/policy rendering intent once post-processing presenters start branching on the same conditions.
- history query mapping -> API query mapper -> `ScanHistoryQuery`
- policy filesystem/path handling -> route-local helpers/modules
- health/stats state -> API response presenters

Do not bypass these seams by passing transport models or DB records through unrelated layers.
Those mappings should live in adapters, not inside the application contracts themselves.

## Command and API Flow

Preferred flow for scan execution:

1. Adapter parses input.
2. Adapter maps input into application request types.
3. Adapter calls application use cases such as `RunScan`, `EvaluateCompliance`, `EvaluatePolicy`, and `StoreScanResults`.
4. Application returns stable output contracts when useful, such as `ScanExecutionReport`.
5. Adapter renders output or serializes the response.
6. Entry points decide exit code or HTTP status.

## Ports and Persistence

CipherRun already has repository traits in [src/db/traits.rs](/Users/seifreed/tools/pentest/CipherRun/src/db/traits.rs). When adding persistence features:

- define or reuse stable application DTOs first
- keep SQLx and pool details inside infrastructure
- avoid introducing new direct dependencies from scanner/application flow to raw DB models unless the model is explicitly a persistence concern

## Review Checklist

Use this checklist in PR review:

- No new dependency from `scanner` to `Args`, API models, or route-specific types.
- No new direct dependency from `policy` or `compliance` to `ScanResults`.
- No new direct dependency from `db` to scanner orchestration types.
- No `println!`, `eprintln!`, or `process::exit` inside application flow.
- Input parsing and validation live in application contracts when they are shared across adapters.
- New tests prefer shared helpers/builders over repeated inline setup.

## Automated Guards

Some rules are already enforced by [tests/architecture_guards.rs](/Users/seifreed/tools/pentest/CipherRun/tests/architecture_guards.rs).

Today those guards verify:

- `policy` does not depend directly on `scanner::ScanResults`
- `compliance` does not depend directly on `scanner::ScanResults`
- `db` does not depend directly on `scanner::ScanResults`
- `application` does not call `process::exit`, print directly, or import adapter-only crates/types
- scanner core files and phases do not depend directly on `Args`
- certificate status filtering does not depend directly on `Args`
- compliance/policy routes reuse the shared HTTP target parsing helper instead of duplicating `host:port` mapping
- scan routes delegate HTTP response DTO construction to `api/presenters`
- history routes delegate HTTP response DTO construction to `api/presenters`
- history routes delegate loading/wiring to `api/adapters` and response DTO construction to `api/presenters`
- history query mapping stays in `api/adapters/history_query.rs` and should not grow DB or presenter responsibilities
- certificate, health, and stats routes delegate HTTP response DTO construction to `api/presenters`
- certificate inventory wiring stays in `api/adapters/certificate_inventory.rs` and should not grow DB query text or presenter responsibilities
- `scanner_formatter` keeps large presentation blocks split into dedicated modules such as `header`, `http_headers`, and `advanced_tls`
- `advanced_tls` should stay physically split by concern once it contains ALPN, intolerance, client-auth, and signature/group display logic
- `header` and `http_headers` should stay focused presentation modules and avoid reabsorbing unrelated formatter concerns once split
- `http_headers` should stay physically split once advanced header analysis grows beyond the core HTTP header output surface
- `db/storage` stays split by domain and `src/db/storage/mod.rs` remains a façade
- certificate route delegates inventory queries to `src/db/certificate_inventory.rs`
- certificate route should stay on the read-side seam (`CertificateInventoryPort`/`CertificateInventoryService`) instead of growing query logic again
- scan presenter delegates export concerns to a dedicated command-side exporter seam
- scan presenter should rely on explicit exporter outcome/render intent instead of branching directly on raw exported flags when post-export notice behavior grows
- scan presenter delegates compliance/policy rendering to a dedicated command-side post presenter seam
- scan presenter delegates main TLS section rendering to a dedicated command-side results presenter seam
- policy routes reuse dedicated filesystem/path helpers instead of inlining metadata loading logic

Run them with:

```bash
cargo test --test architecture_guards
```

## Near-Term Direction

The next architectural improvements should continue in this order:

1. Move more persistence behind application-facing ports.
2. Keep shrinking large presentation and scanner files when they become hotspots again.
3. Split oversized test files where behavior groups are already clear.
4. Add lightweight CI checks or review scripts once the layering stabilizes further.
