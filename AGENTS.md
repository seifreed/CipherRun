<!-- CODEGRAPH_START -->
## CodeGraph

This project has a CodeGraph MCP server (`codegraph_*` tools) configured. CodeGraph is a tree-sitter-parsed knowledge graph of every symbol, edge, and file. Reads are sub-millisecond and return structural information grep cannot.

### When to prefer codegraph over native search

Use codegraph for **structural** questions — what calls what, what would break, where is X defined, what is X's signature. Use native grep/read only for **literal text** queries (string contents, comments, log messages) or after you already have a specific file open.

| Question | Tool |
|---|---|
| "Where is X defined?" / "Find symbol named X" | `codegraph_search` |
| "What calls function Y?" | `codegraph_callers` |
| "What does Y call?" | `codegraph_callees` |
| "How does X reach/become Y? / trace the flow from X to Y" | `codegraph_trace` (one call = the whole path, incl. callback/React/JSX dynamic hops) |
| "What would break if I changed Z?" | `codegraph_impact` |
| "Show me Y's signature / source / docstring" | `codegraph_node` |
| "Give me focused context for a task/area" | `codegraph_context` |
| "See several related symbols' source at once" | `codegraph_explore` |
| "What files exist under path/" | `codegraph_files` |
| "Is the index healthy?" | `codegraph_status` |

### Rules of thumb

- **Answer directly — don't delegate exploration.** For "how does X work" / architecture questions, answer with 2-3 codegraph calls: `codegraph_context` first, then ONE `codegraph_explore` for the source of the symbols it surfaces. For a specific **flow** ("how does X reach Y") start with `codegraph_trace` from→to — one call returns the whole path with dynamic hops bridged — then ONE `codegraph_explore` for the bodies; don't rebuild the path with `codegraph_search` + `codegraph_callers`. Codegraph IS the pre-built index, so spawning a separate file-reading sub-task/agent — or running a grep + read loop — repeats work codegraph already did and costs more for the same answer.
- **Trust codegraph results.** They come from a full AST parse. Do NOT re-verify them with grep — that's slower, less accurate, and wastes context.
- **Don't grep first** when looking up a symbol by name. `codegraph_search` is faster and returns kind + location + signature in one call.
- **Don't chain `codegraph_search` + `codegraph_node`** when you just want context — `codegraph_context` is one call.
- **Don't loop `codegraph_node` over many symbols** — one `codegraph_explore` call returns several symbols' source grouped in a single capped call, while each separate Read call re-reads the whole context and costs far more.
- **Index lag**: the file watcher debounces ~500ms behind writes; don't re-query immediately after editing a file in the same turn.

### If `.codegraph/` doesn't exist

The MCP server returns "not initialized." Ask the user: *"I notice this project doesn't have CodeGraph initialized. Want me to run `codegraph init -i` to build the index?"*
<!-- CODEGRAPH_END -->

@/Users/seifreed/.codex/RTK.md

## README upkeep

Keep each project's README aligned with every functional advancement. Update it in the same change as the code, tests, and support evidence; describe user-visible behavior and support limits accurately, and do not promote bounded evidence into a broader support claim.

## Main-only publishing

For r2morph, integrate work into `main` and push only `main` (`git push origin main`). Never force-push. Before deleting a branch, verify its commits are reachable from `main`; remove integrated work branches after publishing.

## Git and Rust build hygiene

- Commit messages MUST follow the [Conventional Commits 1.0.0 specification](https://www.conventionalcommits.org/en/v1.0.0/#specification).
- When the Rust build output directory `target/` exceeds 80 GB, automatically run `cargo clean` to reclaim build artifacts.

## Stack lifecycle and EOL checks

- Before changing or validating the stack, identify its languages, runtimes, base operating-system images, databases, and other runtime products from manifests, CI, containers, and deployment files.
- For each product tracked by endoflife.date, run `eol-cli products get <product>` (or comma-separated product names) and inspect every release used by development, CI, packaging, and deployment. Do not infer support status from a version number or an old CI job.
- Always use the newest available release that is currently active/non-EOL as the primary development and CI version. Prefer the newest active release (the one with the latest version), not an older release merely because its EOL date is farther away. Confirm the exact version with the relevant runtime's version command.
- Upgrade the declared minimum/runtime constraints and pinned container images when they have reached EOL. Keep compatibility jobs only for versions the project intentionally supports; remove EOL compatibility targets or raise the minimum version instead of treating an EOL release as a supported baseline.
- Before upgrading a stack component, check dependency and platform compatibility, update manifests, lockfiles, CI, containers, and user-facing support documentation together, then run the relevant tests/builds. Do not blindly change unrelated third-party dependencies.
- Re-run these checks when adding or changing stack components and during release preparation. Record any unavailable eol-cli product or intentional pinned exception with its owner, reason, and review condition.

### Rust lifecycle

- Run `eol-cli products get rust` before Rust development or validation. Use its newest active/non-EOL release for local work, CI, and builder images; confirm with `rustc --version`.
- Do not retain an EOL Rust MSRV/CI target as a compatibility promise. Raise `rust-version` and update CI/docs when that target becomes EOL, unless the project explicitly changes its support policy.

### Python lifecycle

- Run `eol-cli products get python` before Python development or validation. Use its newest active/non-EOL release for local work and CI, and test the declared minimum supported Python separately while it remains active.
- Keep `requires-python`, package metadata, tox, CI, and README support claims aligned. Raise the minimum and remove EOL Python jobs when the minimum release reaches EOL.

## Logging & Observability — Mandatory Development Rules

**These rules are mandatory for all new code, bug fixes, refactoring, and architectural changes.**

Logging and observability are core architectural requirements, not optional enhancements. Every change MUST preserve or improve the project's existing observability standards.

### 1. Mandatory Instrumentation

- Every new feature MUST include appropriate logging for significant operations, state transitions, failures, and outcomes.
- Every modified feature MUST preserve or improve its existing logging.
- Every new integration, background task, scheduled job, or external operation MUST provide sufficient diagnostic information.
- Application startup, shutdown, initialization failures, and critical lifecycle events MUST be observable.
- Significant operations SHOULD include execution duration and outcome when useful.
- Logging MUST be proportional to operational relevance. Do not log every function call unnecessarily.

### 2. Logging Architecture

- ALWAYS use the project's established logging abstraction, configuration, and conventions.
- NEVER introduce independent logging implementations without architectural justification.
- NEVER use `print`, `console.log`, `console.error`, or equivalent statements for production diagnostics when an established logger exists.
- CLI applications MUST keep functional stdout output separate from diagnostic logging.
- Prefer structured logging and stable, machine-readable event names.
- Logging MUST remain decoupled from business logic.
- Logging MUST NOT introduce unnecessary dependencies or infrastructure.

### 3. Logging Levels

Use logging levels consistently:

- TRACE: highly detailed execution diagnostics.
- DEBUG: technical information useful during debugging.
- INFO: significant successful operations and lifecycle events.
- WARN: unexpected but recoverable conditions.
- ERROR: failed operations requiring investigation.
- FATAL/CRITICAL: failures preventing continued operation, where supported.

NEVER use ERROR for expected business outcomes.

NEVER use INFO or ERROR for excessive routine diagnostic output.

### 4. Structured Context & Correlation

Relevant log events SHOULD include, where applicable:

- Timestamp (UTC).
- Severity level.
- Component or module.
- Stable event name.
- Operation name.
- Outcome.
- Duration.
- Correlation/request ID.
- Trace/span ID when tracing is enabled.
- Error type and code.

- Preserve correlation context across asynchronous boundaries when applicable.
- NEVER generate fake trace or span identifiers.
- Prefer consistent structured fields over string concatenation.
- Avoid high-cardinality or unnecessary contextual data.

### 5. Security & Privacy

- NEVER log passwords, credentials, tokens, API keys, session cookies, private keys, or other secrets.
- NEVER log unnecessary personal, confidential, or sensitive information.
- NEVER log complete request/response bodies by default.
- Apply redaction and data minimization before logging.
- Treat untrusted log data as potentially malicious.
- Prevent log injection and unsafe serialization.
- Stack traces MUST NOT expose sensitive data.
- Security-relevant actions MUST be auditable when required by the project's threat model.
- Security audit trails MUST NOT be treated as interchangeable with diagnostic logs.

### 6. Error Handling

- NEVER silently swallow unexpected exceptions.
- Log errors at the appropriate architectural boundary.
- Include actionable diagnostic context without exposing secrets.
- Preserve original error causes.
- Avoid logging the same exception repeatedly across layers.
- Expected errors MUST be handled without unnecessary error-level logging.
- Unhandled failures MUST be observable at the appropriate application boundary.

### 7. Performance & Reliability

- Logging MUST NOT significantly degrade application performance.
- Avoid expensive serialization when the configured log level is disabled.
- Avoid excessive logging inside hot paths, loops, and high-frequency events.
- Use sampling, rate limiting, or aggregation where appropriate.
- Logging failures MUST NOT crash the application unless explicitly required by audit or compliance guarantees.
- Respect the project's existing rotation, retention, buffering, and output policies.
- Offline-first applications MUST NOT depend on external logging services.

### 8. Testing Requirements

Whenever a change introduces or modifies observable behavior:

- Add or update tests for relevant log events.
- Verify correct severity and structured fields.
- Verify sensitive information is not exposed.
- Verify correlation propagation when applicable.
- Verify error paths remain observable.
- Ensure logging changes do not alter business behavior.

Tests SHOULD validate structured event properties rather than brittle human-readable message strings.

### 9. Definition of Done

**A development task MUST NOT be considered complete until:**

1. Relevant new operations are appropriately instrumented.
2. Existing observability has not regressed.
3. Errors and important outcomes can be diagnosed.
4. Logs follow established naming, severity, and structural conventions.
5. No sensitive information is exposed.
6. Relevant logging tests pass.
7. No unnecessary logging noise or performance regressions are introduced.
8. Logging documentation is updated when conventions or architecture change.

Before completing any development task, explicitly review its logging and observability impact.

If no additional logging is necessary, preserve the existing architecture and do not add artificial events.

**Golden Rule: Every significant operation must be diagnosable without modifying the source code or reproducing the issue with additional print statements.**
