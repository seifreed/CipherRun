use std::fs;
use std::path::{Path, PathBuf};

fn rust_files_in(dir: &str) -> Vec<PathBuf> {
    fn collect(dir: &Path, files: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                collect(&path, files);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                files.push(path);
            }
        }
    }

    let mut files = Vec::new();
    collect(Path::new(dir), &mut files);
    files.sort();
    files
}

fn assert_no_forbidden_pattern(dir: &str, forbidden_patterns: &[&str], context: &str) {
    let mut violations = Vec::new();

    for file in rust_files_in(dir) {
        let contents = fs::read_to_string(&file).unwrap();
        for pattern in forbidden_patterns {
            if contents.contains(pattern) {
                violations.push(format!(
                    "{} contains forbidden pattern `{}`",
                    file.display(),
                    pattern
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "{}\n{}",
        context,
        violations.join("\n")
    );
}

fn assert_file_has_no_forbidden_pattern(file: &str, forbidden_patterns: &[&str], context: &str) {
    let contents = fs::read_to_string(file).unwrap();
    let violations: Vec<String> = forbidden_patterns
        .iter()
        .filter(|pattern| contents.contains(**pattern))
        .map(|pattern| format!("{file} contains forbidden pattern `{pattern}`"))
        .collect();

    assert!(
        violations.is_empty(),
        "{}\n{}",
        context,
        violations.join("\n")
    );
}

fn assert_file_has_required_pattern(file: &str, required_pattern: &str, context: &str) {
    let contents = fs::read_to_string(file).unwrap();
    assert!(
        contents.contains(required_pattern),
        "{}\n{} must contain required pattern `{}`",
        context,
        file,
        required_pattern
    );
}

#[test]
fn policy_and_compliance_do_not_depend_on_scan_results_directly() {
    assert_no_forbidden_pattern(
        "src/policy",
        &[
            "crate::scanner::ScanResults",
            "use crate::scanner::ScanResults",
        ],
        "Policy layer must consume stable assessment views, not scanner::ScanResults directly.",
    );
    assert_no_forbidden_pattern(
        "src/compliance",
        &[
            "crate::scanner::ScanResults",
            "use crate::scanner::ScanResults",
        ],
        "Compliance layer must consume stable assessment views, not scanner::ScanResults directly.",
    );
}

#[test]
fn db_layer_does_not_depend_on_scan_results_directly() {
    assert_no_forbidden_pattern(
        "src/db",
        &[
            "crate::scanner::ScanResults",
            "use crate::scanner::ScanResults",
        ],
        "DB layer must depend on persistence DTOs or records, not scanner::ScanResults directly.",
    );
}

#[test]
fn db_store_entrypoint_uses_persisted_scan_contract() {
    assert_file_has_required_pattern(
        "src/db/mod.rs",
        "pub async fn store_scan(&self, results: &PersistedScan)",
        "DB entrypoint should continue to use PersistedScan as the persistence contract.",
    );
}

#[test]
fn db_mod_stays_as_façade_instead_of_reabsorbing_helpers() {
    assert_file_has_no_forbidden_pattern(
        "src/db/mod.rs",
        &[
            "async fn store_protocols(",
            "async fn store_ciphers(",
            "async fn store_vulnerabilities(",
            "async fn store_ratings(",
            "async fn store_certificates(",
            "pub async fn get_scan_history(",
            "pub async fn get_latest_scan(",
            "pub async fn cleanup_old_scans(",
        ],
        "db/mod.rs should remain a façade and delegate detailed storage/history helpers to dedicated infrastructure modules.",
    );
}

#[test]
fn db_storage_is_split_by_domain_modules() {
    for file in [
        "src/db/storage/mod.rs",
        "src/db/storage/protocols_ciphers.rs",
        "src/db/storage/findings.rs",
        "src/db/storage/certificates/mod.rs",
        "src/db/storage/certificates/lookup.rs",
        "src/db/storage/certificates/insert.rs",
        "src/db/storage/certificates/link.rs",
        "src/db/history.rs",
    ] {
        assert!(
            Path::new(file).exists(),
            "Expected infrastructure module to exist: {}",
            file
        );
    }
}

#[test]
fn db_storage_mod_remains_a_small_module_facade() {
    let contents = fs::read_to_string("src/db/storage/mod.rs").unwrap();
    let line_count = contents.lines().count();

    assert!(
        line_count <= 20,
        "src/db/storage/mod.rs should stay a small façade module, found {} lines",
        line_count
    );
    assert!(
        !contents.contains("impl CipherRunDatabase"),
        "src/db/storage/mod.rs should only declare domain modules, not reabsorb storage implementations"
    );
}

#[test]
fn db_history_remains_a_wrapper_without_raw_sql() {
    assert_file_has_no_forbidden_pattern(
        "src/db/history.rs",
        &["sqlx::query", "sqlx::query_as", "SELECT "],
        "db/history.rs should remain a thin infrastructure wrapper over repositories, not a second home for raw SQL.",
    );
    assert_file_has_required_pattern(
        "src/db/history.rs",
        "self.scan_repo",
        "db/history.rs should stay as a wrapper around the scan repository rather than growing independent query paths.",
    );
}

#[test]
fn db_certificate_storage_stays_focused_on_certificate_persistence() {
    assert_no_forbidden_pattern(
        "src/db/storage/certificates",
        &[
            "store_protocols(",
            "store_ciphers(",
            "store_vulnerabilities(",
            "store_ratings(",
            "get_scan_history(",
        ],
        "db/storage/certificates.rs should remain focused on certificate persistence concerns only.",
    );
    assert_file_has_required_pattern(
        "src/db/storage/certificates/mod.rs",
        "mod insert;",
        "Certificate storage should stay physically split by responsibility instead of growing back into one hotspot file.",
    );
    assert_file_has_required_pattern(
        "src/db/storage/certificates/mod.rs",
        "mod lookup;",
        "Certificate storage should keep lookup logic in a dedicated submodule.",
    );
    assert_file_has_required_pattern(
        "src/db/storage/certificates/mod.rs",
        "mod link;",
        "Certificate storage should keep scan-certificate linking logic in a dedicated submodule.",
    );
    assert_file_has_required_pattern(
        "src/db/storage/certificates/lookup.rs",
        "build_certificate_lookup_columns",
        "Certificate lookup storage should keep its query column seam explicit once helper coordination appears.",
    );
    assert_file_has_required_pattern(
        "src/db/storage/certificates/insert.rs",
        "build_certificate_insert_columns",
        "Certificate insert storage should keep its insert column seam explicit once helper coordination appears.",
    );
    assert_file_has_required_pattern(
        "src/db/storage/certificates/link.rs",
        "build_scan_certificate_columns",
        "Certificate link storage should keep its insert column seam explicit once helper coordination appears.",
    );
}

#[test]
fn certificate_routes_keep_query_building_out_of_handlers() {
    assert_file_has_required_pattern(
        "src/api/routes/certificates.rs",
        "use crate::api::adapters::certificate_inventory::",
        "Certificate route should delegate inventory wiring/access helpers to a shared API adapter/composition module.",
    );
    assert_file_has_required_pattern(
        "src/api/adapters/certificate_inventory.rs",
        "CertificateInventoryService",
        "Certificate inventory access helper should use the infrastructure service instead of inlining pool logic across handlers.",
    );
    assert_file_has_required_pattern(
        "src/application/ports.rs",
        "pub trait CertificateInventoryPort",
        "Application ports should expose an explicit certificate inventory query port instead of leaving the seam only inside infrastructure.",
    );
    assert_file_has_required_pattern(
        "src/db/certificate_inventory.rs",
        "impl<'a> CertificateInventoryPort for CertificateInventoryService<'a>",
        "Certificate inventory infrastructure should implement the application-facing inventory port.",
    );
    assert_file_has_required_pattern(
        "src/api/adapters/certificate_inventory.rs",
        "inventory_service_from_state",
        "Certificate inventory access helper should keep infrastructure wiring in a small helper instead of repeating pool extraction in each handler.",
    );
    assert_file_has_required_pattern(
        "src/api/adapters/certificate_inventory.rs",
        "CertificateInventoryPort",
        "Certificate inventory access helper should depend on the explicit inventory port at the adapter seam.",
    );
    assert_file_has_required_pattern(
        "src/db/certificate_inventory.rs",
        "async fn fetch_certificate_list_postgres(",
        "Certificate inventory infrastructure should keep backend-specific queries in dedicated helpers.",
    );
    assert_file_has_required_pattern(
        "src/db/certificate_inventory.rs",
        "async fn fetch_certificate_detail_sqlite(",
        "Certificate inventory infrastructure should keep backend-specific detail queries in dedicated helpers.",
    );
    assert_file_has_no_forbidden_pattern(
        "src/api/routes/certificates.rs",
        &["sqlx::query", "SELECT "],
        "Certificate route should stay as an HTTP adapter and not reabsorb raw SQL or backend query text.",
    );
    assert_file_has_no_forbidden_pattern(
        "src/api/routes/certificates.rs",
        &["state.db_pool.as_ref()", "Database not configured"],
        "Certificate route handlers should not repeat DB pool extraction once the shared inventory access helper exists.",
    );
}

#[test]
fn scan_presenter_delegates_exports_to_dedicated_exporter() {
    assert_file_has_required_pattern(
        "src/commands/scan_presenter.rs",
        "use super::scan_exporter::",
        "Scan presenter should delegate file export concerns to a dedicated exporter helper.",
    );
    assert_file_has_required_pattern(
        "src/commands/scan_exporter.rs",
        "pub struct ScanExporter",
        "Scan exporter helper should remain available as the command-side export seam.",
    );
    assert_file_has_required_pattern(
        "src/commands/scan_exporter.rs",
        "has_export_targets",
        "Scan exporter should keep the export-target seam explicit instead of open-coding target checks in multiple places.",
    );
    assert_file_has_required_pattern(
        "src/commands/scan_exporter.rs",
        "has_multi_ip_json_target",
        "Scan exporter should keep multi-IP export intent explicit instead of open-coding target checks in multiple places.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "should_render_export_spacing_for(&self, exported: bool)",
        "Scan notice view should expose explicit spacing/render intent once the presenter no longer branches directly on exporter internals.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "has_multi_ip_export_data",
        "ScanCliView should expose export-relevant intent for presenters and exporters instead of forcing repeated raw-result checks.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "should_build_export_plan",
        "ScanCliView should expose top-level export intent instead of leaving exporters to infer it from raw results.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "pub struct ScanExportView",
        "Application layer should expose a focused export view once CLI exporters no longer need the whole ScanCliView contract.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "has_exportable_results(&self)",
        "ScanExportView should expose explicit exportable-results intent once the exporter no longer needs to infer it from broader CLI state.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "has_multi_ip_export_data(&self)",
        "ScanExportView should expose explicit multi-IP export intent once the exporter no longer needs to infer it from raw result state.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "pub struct ScanNoticeView",
        "Application layer should expose a focused notice view once CLI notice rendering no longer needs the whole ScanCliView contract.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "should_render_any_notice(&self)",
        "ScanNoticeView should expose explicit notice-rendering intent once notice presenters stop inferring it ad hoc from optional IDs.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "has_stored_scan(&self)",
        "ScanNoticeView should expose explicit stored-scan intent once notice rendering no longer needs to infer it ad hoc.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "pub struct ScanPrimaryTlsView",
        "Application layer should expose a focused primary TLS view once result presenters no longer need the whole ScanCliView contract.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "pub struct ScanFeatureView",
        "Application layer should expose a focused feature-results view once result presenters no longer need the whole ScanCliView contract.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "pub struct ScanFingerprintView",
        "Application layer should expose a focused fingerprint/summary view once result presenters no longer need the whole ScanCliView contract.",
    );
    assert_file_has_required_pattern(
        "src/commands/scan_exporter.rs",
        "build_plan_from_view",
        "Scan exporter should accept a focused export view seam instead of depending only on the broader CLI view.",
    );
    assert_file_has_required_pattern(
        "src/commands/scan_exporter.rs",
        "view.has_multi_ip_export_data()",
        "Scan exporter should rely on explicit export-view intent for multi-IP artifacts instead of recomputing it locally.",
    );
    assert_file_has_required_pattern(
        "src/commands/scan_results_presenter/mod.rs",
        "primary_tls_view()",
        "Scan results presenter should consume a focused primary TLS view once the CLI contract exposes one.",
    );
    assert_file_has_required_pattern(
        "src/commands/scan_results_presenter/mod.rs",
        "feature_view()",
        "Scan results presenter should consume a focused feature view once the CLI contract exposes one.",
    );
    assert_file_has_required_pattern(
        "src/commands/scan_results_presenter/mod.rs",
        "fingerprint_view()",
        "Scan results presenter should consume a focused fingerprint view once the CLI contract exposes one.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "pub struct ScanPostView",
        "Application layer should expose a focused post-processing view once the post presenter no longer needs the whole ScanPostProcessingView contract.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "compliance_failed(&self)",
        "ScanPostView should expose explicit compliance failure intent once the post presenter no longer needs to infer it ad hoc.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "policy_failed(&self)",
        "ScanPostView should expose explicit policy failure intent once the post presenter no longer needs to infer it ad hoc.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "has_failures(&self)",
        "ScanPostView should expose aggregated failure intent once post presenters stop recomputing failure checks locally.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "should_return_failure_exit(&self)",
        "ScanPostView should expose explicit failure-exit intent once the post presenter no longer needs to recompute it locally.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "should_render_policy_failure_notice(&self)",
        "ScanPostView should expose explicit policy-failure notice intent once the post presenter stops branching on raw policy/enforcement details.",
    );
    assert_file_has_required_pattern(
        "src/commands/scan_presenter.rs",
        "post_view()",
        "Scan presenter should consume a focused post view once the CLI contract exposes one.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "should_skip_artifacts(&self)",
        "ScanCliView should expose explicit artifact-skipping intent once the presenter stops deciding locally when post-processing failures block exports/notices.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "should_render_post_processing(&self)",
        "ScanCliView should expose explicit post-processing render intent once the presenter stops invoking the post presenter unconditionally.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "should_render_artifact_notices(&self)",
        "ScanCliView should expose explicit artifact-notice intent once the presenter stops deciding locally when artifact-related notices are worth rendering.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "should_render_artifact_notices_for(&self, has_artifacts: bool)",
        "ScanCliView should expose explicit artifact-notice gating intent once the presenter stops combining broad notice intent with local artifact-option checks.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "should_render_post_scan_notices_for(&self, has_artifacts: bool)",
        "ScanCliView should expose explicit post-scan notice gating intent once the presenter stops recomposing the top-level notice decision from local artifact checks.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "should_render_post_scan_export_spacing_for(",
        "ScanCliView should expose explicit export-spacing gating intent once the presenter stops combining raw exporter outcomes with notice-view checks locally.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "stored_scan_id_for_post_scan_notices(&self, has_artifacts: bool)",
        "ScanCliView should expose notice-ready stored-scan data for post-scan notice flows once the presenter stops combining artifact gating with raw notice-view storage checks locally.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "stored_scan_id_for_artifact_notices(&self)",
        "ScanCliView should expose artifact-notice-ready stored-scan data once the presenter stops threading a hard-coded artifact-presence flag into post-scan storage notice checks.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "should_render_post_scan_export_spacing(&self, exported: bool)",
        "ScanCliView should expose artifact-notice export-spacing intent once the presenter stops threading a hard-coded artifact-presence flag into spacing checks.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "should_handle_artifacts(&self)",
        "ScanCliView should expose explicit artifact-handling intent once the presenter stops branching directly on the inverse of artifact-skipping rules.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "should_export_artifacts(&self)",
        "ScanCliView should expose explicit export-attempt intent once the presenter stops deciding locally whether artifact handling and exportable data justify invoking the exporter.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "should_render_storage_notice_for(&self, stored_scan_id: Option<i64>)",
        "ScanNoticeView should expose explicit storage-notice intent once the presenter stops open-coding optional-ID checks around notice rendering.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "should_render_storage_notice(&self)",
        "ScanNoticeView should expose direct storage-notice intent once the presenter stops threading redundant stored-scan IDs through artifact outcomes.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "stored_scan_id_for_notice(&self)",
        "ScanNoticeView should expose explicit notice-ready stored-scan data once the presenter stops composing storage-intent checks with raw optional IDs.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "should_render_export_spacing_for(&self, exported: bool)",
        "ScanNoticeView should expose explicit export-spacing intent once the presenter stops branching directly on exporter booleans around notice rendering.",
    );
    assert_file_has_required_pattern(
        "src/commands/scan_post_presenter.rs",
        "should_return_failure_exit()",
        "Scan post presenter should rely on explicit post-view exit intent instead of re-deriving failure behavior ad hoc.",
    );
    assert_file_has_required_pattern(
        "src/commands/scan_post_presenter.rs",
        "should_render_policy_failure_notice()",
        "Scan post presenter should rely on explicit post-view notice intent instead of branching directly on policy violations and enforcement flags.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "should_render_post_scan_notices",
        "ScanCliView should expose post-scan notice intent instead of leaving notice decisions to ad hoc checks in presenters.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "should_render_primary_tls_sections",
        "ScanCliView should expose grouped TLS section intent instead of forcing results presenters to reconstruct those decisions.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "should_render_primary_tls_view(&self)",
        "ScanCliView should expose explicit primary-view render intent once results presenters stop combining grouped section intent with local subview checks.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "should_render_detailed_results(&self)",
        "ScanCliView should expose explicit detailed-results intent once results presenters stop locally negating summary-only behavior.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "should_render_results_summary_only(&self)",
        "ScanCliView should expose explicit summary-only intent once results presenters stop locally negating detailed-results behavior.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "should_render_results(&self)",
        "ScanCliView should expose explicit top-level results-render intent once the outer presenter stops invoking the results presenter unconditionally.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "should_render_results_summary(&self)",
        "ScanCliView should expose explicit results-summary intent once the results presenter stops deciding locally when to render the final summary block.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "should_render_feature_view(&self)",
        "ScanCliView should expose explicit feature-view render intent once results presenters stop combining grouped section intent with local subview checks.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "should_render_fingerprint_view(&self)",
        "ScanCliView should expose explicit fingerprint-view render intent once results presenters stop combining grouped section intent with local subview checks.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "should_render_compliance_section",
        "Scan post-processing view should expose compliance rendering intent instead of leaving post presenters to infer it ad hoc.",
    );
    assert_file_has_required_pattern(
        "src/application/scan_execution.rs",
        "should_render_policy_section",
        "Scan post-processing view should expose policy rendering intent instead of leaving post presenters to infer it ad hoc.",
    );
    assert_file_has_required_pattern(
        "src/commands/scan_presenter.rs",
        "use super::scan_post_presenter::",
        "Scan presenter should delegate compliance/policy rendering to a dedicated post presenter helper.",
    );
    assert_file_has_required_pattern(
        "src/commands/scan_post_presenter.rs",
        "pub struct ScanPostPresenter",
        "Scan post presenter helper should remain available as the command-side compliance/policy seam.",
    );
    assert_file_has_required_pattern(
        "src/commands/scan_presenter.rs",
        "use super::scan_results_presenter::",
        "Scan presenter should delegate TLS result rendering to a dedicated results presenter helper.",
    );
    assert_file_has_required_pattern(
        "src/commands/scan_results_presenter/mod.rs",
        "pub struct ScanResultsPresenter",
        "Scan results presenter helper should remain available as the command-side TLS rendering seam.",
    );
    assert_file_has_required_pattern(
        "src/commands/scan_results_presenter/mod.rs",
        "mod primary;",
        "Scan results presenter should stay physically split once the TLS rendering surface grows.",
    );
    assert_file_has_required_pattern(
        "src/commands/scan_results_presenter/mod.rs",
        "mod feature;",
        "Scan results presenter should keep feature rendering in a dedicated submodule.",
    );
    assert_file_has_required_pattern(
        "src/commands/scan_results_presenter/mod.rs",
        "mod fingerprint;",
        "Scan results presenter should keep fingerprint/rating rendering in a dedicated submodule.",
    );
    assert_file_has_required_pattern(
        "src/commands/scan_results_presenter/primary.rs",
        "render_primary_tls_sections",
        "Scan results presenter should keep internal section seams explicit as the TLS output surface grows.",
    );
    assert_file_has_required_pattern(
        "src/commands/scan_results_presenter/mod.rs",
        "should_render_primary_tls_view()",
        "Scan results presenter should rely on explicit CLI primary-view intent instead of recombining grouped section intent with local subview checks.",
    );
    assert_file_has_required_pattern(
        "src/commands/scan_results_presenter/mod.rs",
        "should_render_results_summary_only()",
        "Scan results presenter should rely on explicit CLI summary-only intent instead of locally negating detailed-results behavior.",
    );
    assert_file_has_required_pattern(
        "src/commands/scan_results_presenter/mod.rs",
        "should_render_results_summary()",
        "Scan results presenter should rely on explicit CLI summary intent instead of deciding locally when the summary block should render after detailed sections.",
    );
    assert_file_has_required_pattern(
        "src/commands/scan_presenter.rs",
        "should_render_results()",
        "Scan presenter should rely on explicit CLI results-render intent instead of invoking the results presenter unconditionally.",
    );
    assert_file_has_required_pattern(
        "src/commands/scan_results_presenter/mod.rs",
        "should_render_feature_view()",
        "Scan results presenter should rely on explicit CLI feature-view intent instead of recombining grouped section intent with local subview checks.",
    );
    assert_file_has_required_pattern(
        "src/commands/scan_results_presenter/mod.rs",
        "should_render_fingerprint_view()",
        "Scan results presenter should rely on explicit CLI fingerprint-view intent instead of recombining grouped section intent with local subview checks.",
    );
    assert_file_has_required_pattern(
        "src/commands/scan_presenter.rs",
        "use super::scan_notice_presenter::",
        "Scan presenter should delegate storage/export notices to a dedicated notice presenter helper.",
    );
    assert_file_has_required_pattern(
        "src/commands/scan_notice_presenter.rs",
        "pub struct ScanNoticePresenter",
        "Scan notice presenter helper should remain available as the command-side notice seam.",
    );
    assert_file_has_no_forbidden_pattern(
        "src/commands/scan_post_presenter.rs",
        &["std::fs::write(", "display_protocol_results("],
        "Scan post presenter should stay focused on compliance/policy output and not reabsorb exports or TLS section rendering.",
    );
    assert_no_forbidden_pattern(
        "src/commands/scan_results_presenter",
        &[
            "std::fs::write(",
            "Reporter::to_",
            "ComplianceStatus::",
            "println!(",
        ],
        "Scan results presenter should stay focused on TLS/result rendering and not reabsorb exports or compliance formatting.",
    );
    assert_file_has_no_forbidden_pattern(
        "src/commands/scan_exporter.rs",
        &[
            "Reporter::to_",
            "display_protocol_results(",
            "ComplianceStatus::",
            "state.db_pool",
            "policy_result(",
        ],
        "Scan exporter should stay focused on artifact generation and not reabsorb compliance or TLS rendering responsibilities.",
    );
    assert_file_has_no_forbidden_pattern(
        "src/commands/scan_notice_presenter.rs",
        &[
            "std::fs::write(",
            "Reporter::to_",
            "display_protocol_results(",
            "ComplianceStatus::",
            "exported()",
        ],
        "Scan notice presenter should stay focused on scan notices and not reabsorb exports, compliance formatting, or TLS rendering.",
    );
    assert_file_has_required_pattern(
        "src/commands/scan_presenter.rs",
        "should_render_post_scan_notices_for",
        "Scan presenter should rely on explicit CLI post-scan notice intent instead of recomposing notice gating from local artifact checks.",
    );
    assert_file_has_required_pattern(
        "src/commands/scan_presenter.rs",
        "stored_scan_id_for_artifact_notices(",
        "Scan presenter should rely on explicit CLI artifact-notice stored-scan intent instead of threading a hard-coded artifact flag into post-scan notice checks.",
    );
    assert_file_has_required_pattern(
        "src/commands/scan_presenter.rs",
        "should_render_post_scan_export_spacing(",
        "Scan presenter should rely on explicit CLI artifact-notice export-spacing intent instead of threading a hard-coded artifact flag into spacing checks.",
    );
    assert_file_has_required_pattern(
        "src/commands/scan_presenter.rs",
        "should_export_artifacts()",
        "Scan presenter should rely on explicit CLI export intent instead of deciding locally whether the export view is worth consulting.",
    );
    assert_file_has_no_forbidden_pattern(
        "src/commands/scan_presenter.rs",
        &["ScanPostProcessingView"],
        "Scan presenter should not keep threading the broader post-processing contract into artifact handling once notice/export seams are driven by focused CLI views.",
    );
    assert_file_has_no_forbidden_pattern(
        "src/commands/scan_presenter.rs",
        &[
            "std::fs::write(",
            "Reporter::to_",
            "display_protocol_results(",
            "ComplianceStatus::",
            "Scan results stored in database",
        ],
        "Scan presenter should not reabsorb direct filesystem export, compliance formatting, or TLS section rendering responsibilities.",
    );
    assert_no_forbidden_pattern(
        "src/commands/scan_results_presenter",
        &[
            "std::fs::write(",
            "Reporter::to_",
            "ComplianceStatus::",
            "std::fs::",
        ],
        "Scan results presenter should remain a pure rendering helper and not reabsorb export or compliance responsibilities.",
    );
}

#[test]
fn scanner_formatter_keeps_split_presentation_modules() {
    assert_file_has_required_pattern(
        "src/output/scanner_formatter.rs",
        "mod advanced_tls;",
        "Scanner formatter should keep advanced TLS presentation in a dedicated submodule once the formatter surface grows.",
    );
    assert_file_has_required_pattern(
        "src/output/scanner_formatter.rs",
        "mod header;",
        "Scanner formatter should keep header/progress presentation in a dedicated submodule once the formatter surface grows.",
    );
    assert_file_has_required_pattern(
        "src/output/scanner_formatter.rs",
        "mod http_headers;",
        "Scanner formatter should keep HTTP header presentation in a dedicated submodule once the formatter surface grows.",
    );
    assert_file_has_no_forbidden_pattern(
        "src/output/scanner_formatter.rs",
        &[
            "pub fn display_http_headers_results(",
            "pub fn display_alpn_results(",
            "pub fn display_signature_results(",
            "pub fn display_client_cas_results(",
        ],
        "scanner_formatter.rs should stay as a facade and not reabsorb advanced TLS or HTTP header presentation blocks once they are split out.",
    );
    assert_file_has_required_pattern(
        "src/output/scanner_formatter/advanced_tls/mod.rs",
        "mod alpn;",
        "Advanced TLS presentation should stay physically split once the formatter surface grows.",
    );
    assert_file_has_required_pattern(
        "src/output/scanner_formatter/advanced_tls/mod.rs",
        "mod client_auth;",
        "Advanced TLS presentation should keep client authentication display in a dedicated submodule.",
    );
    assert_file_has_required_pattern(
        "src/output/scanner_formatter/advanced_tls/mod.rs",
        "mod intolerance;",
        "Advanced TLS presentation should keep intolerance display in a dedicated submodule.",
    );
    assert_file_has_required_pattern(
        "src/output/scanner_formatter/advanced_tls/mod.rs",
        "mod signatures_groups;",
        "Advanced TLS presentation should keep signature/group display in a dedicated submodule.",
    );
    assert_file_has_no_forbidden_pattern(
        "src/output/scanner_formatter/advanced_tls/alpn.rs",
        &["display_http_headers_results(", "print_scan_header("],
        "ALPN formatter module should stay focused on ALPN presentation only.",
    );
    assert_file_has_no_forbidden_pattern(
        "src/output/scanner_formatter/advanced_tls/client_auth.rs",
        &["display_alpn_results(", "display_http_headers_results("],
        "Client-auth formatter module should stay focused on client CA presentation only.",
    );
    assert_file_has_no_forbidden_pattern(
        "src/output/scanner_formatter/advanced_tls/signatures_groups.rs",
        &[
            "display_http_headers_results(",
            "display_client_cas_results(",
        ],
        "Signature/group formatter module should stay focused on signature and key exchange group presentation only.",
    );
    assert_file_has_no_forbidden_pattern(
        "src/output/scanner_formatter/advanced_tls/intolerance.rs",
        &["display_http_headers_results(", "display_group_results("],
        "Intolerance formatter module should stay focused on intolerance presentation only.",
    );
    assert_file_has_no_forbidden_pattern(
        "src/output/scanner_formatter/header.rs",
        &[
            "display_http_headers_results(",
            "display_alpn_results(",
            "display_advanced_header_analysis(",
            "display_hsts_analysis(",
            "display_cookie_analysis(",
        ],
        "Header formatter module should stay focused on scan header/progress concerns only.",
    );
    assert_file_has_no_forbidden_pattern(
        "src/output/scanner_formatter/http_headers/mod.rs",
        &[
            "display_alpn_results(",
            "display_signature_results(",
            "print_scan_header(",
            "display_intolerance_results(",
            "display_cookie_analysis(",
        ],
        "HTTP header formatter module should stay focused on HTTP header presentation only.",
    );
    assert_file_has_required_pattern(
        "src/output/scanner_formatter/http_headers/mod.rs",
        "display_advanced_header_analysis",
        "HTTP header formatter should keep the advanced header analysis seam explicit as the presentation surface grows.",
    );
    assert_file_has_required_pattern(
        "src/output/scanner_formatter/http_headers/mod.rs",
        "mod advanced;",
        "HTTP header formatter should stay physically split once advanced header analysis grows beyond the core surface.",
    );
    assert_file_has_no_forbidden_pattern(
        "src/output/scanner_formatter/http_headers/advanced.rs",
        &[
            "display_alpn_results(",
            "print_scan_header(",
            "display_http_issues(",
            "display_http_response_metadata(",
        ],
        "Advanced HTTP header formatter module should stay focused on advanced header analysis only.",
    );
    assert_file_has_required_pattern(
        "src/output/scanner_formatter/header.rs",
        "print_phase_progress_nl",
        "Header formatter should keep progress/newline rendering explicit as the scan progress surface grows.",
    );
    assert_file_has_required_pattern(
        "src/output/scanner_formatter/header.rs",
        "print_error",
        "Header formatter should keep error-line rendering explicit as the scan progress/header surface grows.",
    );
}

#[test]
fn application_layer_has_no_process_exit_or_console_output() {
    assert_no_forbidden_pattern(
        "src/application",
        &[
            "std::process::exit",
            "process::exit(",
            "println!(",
            "eprintln!(",
            "crate::cli::Args",
            "use crate::cli::Args",
            "clap::",
            "axum::",
            "sqlx::",
        ],
        "Application layer must not own process exit decisions or direct console output.",
    );
}

#[test]
fn scanner_core_does_not_depend_on_args_directly() {
    let forbidden = &[
        "crate::Args",
        "use crate::Args",
        "crate::cli::Args",
        "use crate::cli::Args",
        "clap::",
        "axum::",
        "sqlx::",
    ];

    for file in [
        "src/scanner/mass.rs",
        "src/scanner/config.rs",
        "src/scanner/service.rs",
        "src/scanner/builders.rs",
        "src/scanner/orchestration.rs",
        "src/scanner/results.rs",
    ] {
        assert_file_has_no_forbidden_pattern(
            file,
            forbidden,
            "Scanner core services must consume ScanRequest/config types and must not depend on adapter or DB crates directly.",
        );
    }

    assert_no_forbidden_pattern(
        "src/scanner/phases",
        forbidden,
        "Scanner phases must consume ScanContext and internal contracts, not adapter or DB crates directly.",
    );
}

#[test]
fn certificate_status_does_not_depend_on_args_directly() {
    assert_file_has_no_forbidden_pattern(
        "src/certificates/status.rs",
        &[
            "crate::Args",
            "use crate::Args",
            "crate::cli::Args",
            "use crate::cli::Args",
        ],
        "Certificate status filtering must use stable filter configuration, not Args directly.",
    );
}

#[test]
fn api_routes_reuse_shared_target_input_mapping() {
    let forbidden = &[
        "HostPortInput::parse_with_default_port(",
        "Invalid target format. Expected hostname:port",
    ];

    for file in ["src/api/routes/compliance.rs", "src/api/routes/policies.rs"] {
        assert_file_has_no_forbidden_pattern(
            file,
            forbidden,
            "API routes should reuse shared target parsing/presenter helpers instead of duplicating host:port mapping.",
        );
    }
}

#[test]
fn policy_routes_reuse_shared_policy_storage_helpers() {
    assert_file_has_required_pattern(
        "src/api/routes/policies.rs",
        "use super::policy_storage::",
        "Policy routes should reuse shared policy storage helpers for filesystem/path operations.",
    );
    assert_file_has_required_pattern(
        "src/api/routes/policy_storage.rs",
        "fn read_policy_with_metadata(",
        "Policy storage helper module should own filesystem/metadata loading concerns.",
    );
    assert_file_has_required_pattern(
        "src/api/routes/policies.rs",
        "fn existing_policy_path(",
        "Policy routes should centralize repeated path existence checks once that flow appears in multiple handlers.",
    );
}

#[test]
fn scan_routes_use_shared_presenters_for_http_responses() {
    assert_file_has_no_forbidden_pattern(
        "src/api/routes/scans.rs",
        &["Ok(Json(ScanResponse {", "Ok(Json(ScanStatusResponse {"],
        "Scan routes should delegate response construction to API presenters instead of building response DTOs inline.",
    );
}

#[test]
fn history_routes_use_shared_presenters_for_http_responses() {
    assert_file_has_no_forbidden_pattern(
        "src/api/routes/history.rs",
        &["Ok(Json(ScanHistoryResponse {"],
        "History routes should delegate response construction to API presenters instead of building response DTOs inline.",
    );
    assert_file_has_required_pattern(
        "src/api/routes/history.rs",
        "use crate::api::adapters::history::",
        "History route should delegate DB wiring and loading to a shared API adapter helper.",
    );
    assert_file_has_required_pattern(
        "src/api/adapters/history.rs",
        "ScanHistoryPort",
        "History adapter helper should depend on the application-facing history port instead of route-local SQL.",
    );
    assert_file_has_required_pattern(
        "src/api/routes/history.rs",
        "use crate::api::adapters::history_query::",
        "History route should reuse a dedicated API-side query mapper once request mapping logic exists.",
    );
    assert_file_has_required_pattern(
        "src/api/adapters/history_query.rs",
        "history_query_from_api",
        "History adapter query mapper should centralize route-to-application query mapping once that seam exists.",
    );
    assert_file_has_no_forbidden_pattern(
        "src/api/adapters/history_query.rs",
        &["sqlx::query", "state.db_pool", "present_scan_history("],
        "History query adapter should stay focused on request mapping and not reabsorb DB or presenter concerns.",
    );
    assert_file_has_required_pattern(
        "src/api/adapters/history_query.rs",
        "limit: query.limit",
        "History query adapter should keep request-to-query mapping explicit and local once the seam exists.",
    );
    assert_file_has_required_pattern(
        "src/db/scan_history.rs",
        "impl<'a> ScanHistoryPort for ScanHistoryService<'a>",
        "History infrastructure should implement the application-facing history port.",
    );
    assert_file_has_no_forbidden_pattern(
        "src/api/routes/history.rs",
        &[
            "sqlx::query",
            "SELECT ",
            "state.db_pool.as_ref()",
            "Database not configured",
        ],
        "History route should stay as an HTTP adapter and not reabsorb raw SQL or direct DB pool extraction.",
    );
    assert_file_has_required_pattern(
        "src/api/routes/history.rs",
        "present_scan_history(",
        "History route should continue delegating response DTO construction to the shared presenter seam.",
    );
}

#[test]
fn certificate_routes_use_shared_presenters_for_http_responses() {
    assert_file_has_no_forbidden_pattern(
        "src/api/routes/certificates.rs",
        &["Ok(Json(CertificateListResponse {"],
        "Certificate routes should delegate response construction to API presenters instead of building response DTOs inline.",
    );
    assert_file_has_no_forbidden_pattern(
        "src/api/adapters/certificate_inventory.rs",
        &["sqlx::query", "SELECT ", "present_certificate"],
        "Certificate inventory adapter should stay focused on wiring/access helpers and not reabsorb DB query text or presenter concerns.",
    );
    assert_file_has_required_pattern(
        "src/api/adapters/certificate_inventory.rs",
        "inventory_service_from_state",
        "Certificate inventory adapter should keep infrastructure wiring in one place instead of repeating pool extraction in routes.",
    );
}

#[test]
fn compliance_route_uses_adapter_not_direct_scanner() {
    assert_file_has_no_forbidden_pattern(
        "src/api/routes/compliance.rs",
        &["Scanner::new(", "use crate::scanner::Scanner"],
        "Compliance route must use the compliance adapter instead of creating Scanner directly (dependency inversion).",
    );
}

#[test]
fn health_and_stats_routes_use_shared_presenters_for_http_responses() {
    assert_file_has_no_forbidden_pattern(
        "src/api/routes/health.rs",
        &["Json(HealthResponse {"],
        "Health route should delegate response construction to API presenters instead of building response DTOs inline.",
    );
    assert_file_has_no_forbidden_pattern(
        "src/api/routes/stats.rs",
        &["Json(StatsResponse {"],
        "Stats route should delegate response construction to API presenters instead of building response DTOs inline.",
    );
}
