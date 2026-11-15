# Logging and observability audit

Audit updated: 2026-11-15. The initial score below describes the repository
before the logging changes in commits `d7cee34` through `1fd412f`.

## Initial score

**5.6/10**, the arithmetic mean of the ten dimensions. This is an evidence-based
engineering assessment, not a claim that every one of the repository's 808
indexed source files was manually inspected.

| Dimension | Score | Evidence at the initial audit |
| --- | ---: | --- |
| Architecture and decoupling | 7 | Rust `tracing`/`tracing-subscriber` already centralized event APIs; optional OTLP layer in `src/telemetry.rs`. |
| Functional coverage | 5 | API, queue and scanner modules emitted events, but `crates/cipherrun-worker/src/main.rs` had no subscriber, and coverage varied by component. |
| Event quality | 6 | Useful operational events existed, alongside target/alert-content logs and free-form messages with inconsistent fields. |
| Structure and consistency | 6 | `tracing` supported structured fields, but most events were message interpolation; the main CLI accepted only a bare level. |
| Context and correlation | 4 | API audit events and `X-Request-ID` existed in `src/api/middleware/metrics.rs`; downstream work did not inherit a request span. |
| Security and privacy | 5 | Audit middleware omitted query strings and bodies, but scan target, alert message, WebSocket text and redirect URL content could reach logs. |
| Performance and resilience | 6 | Synchronous stderr/file writer was mutex-protected; no application-managed rotation or retention was present. |
| Configuration and portability | 6 | CLI verbosity, `RUST_LOG`, `--logfile`, and optional OTLP existed; `RUST_LOG` did not accept module directives. |
| Error handling | 5 | Many errors were observable, but some were printed directly and some layers logged raw error or payload text. |
| Testing and verification | 6 | There were middleware tests and broad project tests, but little direct verification of filter behavior, correlation and redaction. |

## Changes verified so far

- `d7cee34`: module-specific `RUST_LOG` filters; focused CLI test passed.
- `0c1e78b`: standalone worker initializes `tracing`; `cargo test -p cipherrun-worker` built successfully but ran zero tests.
- `2970340`: downstream API work runs inside an `http.request` span with request ID, method and path; 30 middleware tests passed.
- `1ff58fd`: scan targets and alert message bodies removed from operational logs; 56 alert tests passed.
- `1fd412f`: WebSocket text and redirect locations removed from logs; focused tests passed (1 WebSocket and 12 HTTP tester tests).

## Current known limitations

- The audit has not yet classified every event or every executable entry point.
- The default formatter is human-readable text, not JSON. Fields are structured at the event API but output configuration does not offer JSON selection.
- API request IDs are generated locally. Incoming W3C `traceparent` is not extracted; distributed trace continuity is available only where an OTLP-enabled trace already exists.
- The local file writer appends but does not rotate or enforce retention. Logging is synchronous and can block on disk I/O.
- The worker has no dedicated regression test asserting emitted error events or initialization behavior.
- A local `cargo audit` run on 2026-11-15 initially reported 44 findings. Compatible updates have removed the Hickory, Rustls, Quinn, zstd and `zip` findings. Resolving `zip` required upgrading optional Swagger UI to 10 and Utoipa to 6; `cargo check --features swagger` passed. One finding remains: `libsqlite3-sys`. The SQLite advisory applies to bundled SQLite before 3.54.0. SQLx currently constrains `libsqlite3-sys` below 0.38, so the fixed 0.39 line is not resolvable without a coordinated upstream or local SQLx integration change.

The current score remains **unrated** until the remaining event inventory and
validation are complete. The initial 5.6 score must not be treated as the final
score.
