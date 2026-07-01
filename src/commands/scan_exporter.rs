use crate::application::ScanExportView;
use crate::{Args, Result};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

const MAX_APPEND_CSV_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExportKind {
    Json,
    MultiIpJson,
    Csv,
    Html,
    Xml,
    RawHello,
}

pub struct ScanExportPlan<'a> {
    pub results: &'a crate::scanner::ScanResults,
    pub json_file: Option<std::path::PathBuf>,
    pub json_pretty: bool,
    pub json_multi_ip: Option<std::path::PathBuf>,
    pub csv_file: Option<std::path::PathBuf>,
    pub html_file: Option<std::path::PathBuf>,
    pub xml_file: Option<std::path::PathBuf>,
}

impl ScanExportPlan<'_> {
    pub fn has_export_targets(&self) -> bool {
        self.json_file.is_some()
            || self.json_multi_ip.is_some()
            || self.csv_file.is_some()
            || self.html_file.is_some()
            || self.xml_file.is_some()
    }

    pub fn has_multi_ip_json_target(&self) -> bool {
        self.json_multi_ip.is_some()
    }
}

pub struct ScanExportOutcome {
    exported: bool,
}

impl ScanExportOutcome {
    pub fn none() -> Self {
        Self { exported: false }
    }

    pub fn exported(&self) -> bool {
        self.exported
    }
}

pub struct ScanExporter<'a> {
    args: &'a Args,
}

impl<'a> ScanExporter<'a> {
    pub fn new(args: &'a Args) -> Self {
        Self { args }
    }

    pub fn build_plan_from_view<'b>(&self, view: ScanExportView<'b>) -> Result<ScanExportPlan<'b>> {
        let bundle_base = self.args.output.output_all.as_ref();
        let mut json_file = self.args.output.json.clone();
        let mut json_multi_ip = if view.has_multi_ip_export_data() {
            self.args.output.json_multi_ip.clone()
        } else {
            None
        };
        let mut csv_file = self.args.output.csv.clone();
        let mut html_file = self.args.output.html.clone();
        let mut xml_file = self.args.output.xml.clone();

        if let Some(base) = bundle_base {
            json_file.get_or_insert_with(|| self.bundle_output_path(base, "json"));
            csv_file.get_or_insert_with(|| self.bundle_output_path(base, "csv"));
            html_file.get_or_insert_with(|| self.bundle_output_path(base, "html"));
            xml_file.get_or_insert_with(|| self.bundle_output_path(base, "xml"));

            if view.has_multi_ip_export_data() {
                json_multi_ip.get_or_insert_with(|| self.bundle_output_path(base, "multi-ip.json"));
            }
        }

        Ok(ScanExportPlan {
            results: view.results(),
            json_file: self.apply_outprefix_option(json_file)?,
            json_pretty: self.args.output.json_pretty,
            json_multi_ip: self.apply_outprefix_option(json_multi_ip)?,
            csv_file: self.apply_outprefix_option(csv_file)?,
            html_file: self.apply_outprefix_option(html_file)?,
            xml_file: self.apply_outprefix_option(xml_file)?,
        })
    }

    pub(crate) fn collection_json_output_path(&self) -> Result<Option<PathBuf>> {
        self.args
            .output
            .json
            .clone()
            .or_else(|| {
                self.args
                    .output
                    .output_all
                    .as_ref()
                    .map(|base| self.bundle_output_path(base, "json"))
            })
            .map(|path| self.apply_outprefix(path))
            .transpose()
    }

    pub fn export(&self, plan: ScanExportPlan<'_>) -> Result<ScanExportOutcome> {
        if !plan.has_export_targets() {
            return Ok(ScanExportOutcome::none());
        }

        let has_multi_ip_json_target = plan.has_multi_ip_json_target();
        let mut exported = false;
        if let Some(json_file) = plan.json_file {
            let json = plan.results.to_json(plan.json_pretty)?;
            self.write_artifact(&json_file, &json, ExportKind::Json)?;
            println!("✓ Results exported to JSON: {}", json_file.display());
            exported = true;
        }

        if has_multi_ip_json_target
            && let Some(json_path) = plan.json_multi_ip
            && let Some(ref report) = plan.results.scan_metadata.multi_ip_report
        {
            use crate::output::json::generate_multi_ip_json;
            let json = generate_multi_ip_json(report, plan.json_pretty)?;
            self.write_artifact(&json_path, &json, ExportKind::MultiIpJson)?;
            println!(
                "✓ Multi-IP report exported to JSON: {}",
                json_path.display()
            );
            exported = true;
        }

        if let Some(csv_file) = plan.csv_file {
            use crate::output::csv;
            let csv = csv::generate_csv(plan.results)?;
            self.write_artifact(&csv_file, &csv, ExportKind::Csv)?;
            println!("✓ Results exported to CSV: {}", csv_file.display());
            exported = true;
        }

        if let Some(html_file) = plan.html_file {
            use crate::output::html;
            let html_content = html::generate_html_report(plan.results)?;
            self.write_artifact(&html_file, &html_content, ExportKind::Html)?;
            println!("✓ Results exported to HTML: {}", html_file.display());
            exported = true;
        }

        if let Some(xml_file) = plan.xml_file {
            use crate::output::xml;
            let xml_content = xml::generate_xml_report(plan.results)?;
            self.write_artifact(&xml_file, &xml_content, ExportKind::Xml)?;
            println!("✓ Results exported to XML: {}", xml_file.display());
            exported = true;
        }

        Ok(ScanExportOutcome { exported })
    }

    /// Export captured raw Client/Server Hello bytes when `--export-hello` is set.
    ///
    /// Each captured Hello is written to `<sanitized-target>.<which>_hello.<ext>`
    /// in the requested format. No-op when the flag is absent or no Hello was
    /// captured (e.g. fingerprinting was disabled or the handshake failed).
    pub fn export_hellos(&self, results: &crate::scanner::ScanResults) -> Result<()> {
        let Some(format_str) = &self.args.fingerprint.export_hello else {
            return Ok(());
        };
        let format = crate::output::hello_export::HelloExportFormat::parse(format_str)?;

        let Some(fingerprints) = &results.fingerprints else {
            return Ok(());
        };

        let base = sanitize_target_filename(&results.target);
        let exports = [
            ("client_hello", fingerprints.client_hello_raw.as_ref()),
            ("server_hello", fingerprints.server_hello_raw.as_ref()),
        ];

        for (label, maybe_bytes) in exports {
            let Some(bytes) = maybe_bytes else {
                continue;
            };
            let path = PathBuf::from(format!("{}.{}.{}", base, label, format.file_extension()));
            self.ensure_write_allowed(&path, ExportKind::RawHello)?;
            fs::write(
                &path,
                crate::output::hello_export::render_hello(bytes, format),
            )?;
            if !self.args.output.quiet {
                println!(
                    "✓ Exported {} ({} bytes) to {}",
                    label,
                    bytes.len(),
                    path.display()
                );
            }
        }

        Ok(())
    }

    pub(crate) fn write_text_file(
        &self,
        path: &Path,
        content: &str,
        kind: &str,
        export_kind: ExportKind,
    ) -> Result<()> {
        self.write_artifact(path, content, export_kind)?;
        println!("✓ Results exported to {}: {}", kind, path.display());
        Ok(())
    }

    fn write_artifact(&self, path: &Path, content: &str, kind: ExportKind) -> Result<()> {
        self.ensure_write_allowed(path, kind)?;

        if self.args.output.append && path.exists() {
            match kind {
                ExportKind::Csv => self.append_csv(path, content)?,
                ExportKind::Json
                | ExportKind::MultiIpJson
                | ExportKind::Html
                | ExportKind::Xml
                | ExportKind::RawHello => {
                    return Err(crate::TlsError::InvalidInput {
                        message: format!(
                            "--append is only supported for CSV exports; cannot append to {}",
                            path.display()
                        ),
                    });
                }
            }
        } else {
            fs::write(path, content)?;
        }

        Ok(())
    }

    fn ensure_write_allowed(&self, path: &Path, kind: ExportKind) -> Result<()> {
        if self.args.output.append && !matches!(kind, ExportKind::Csv) {
            return Err(crate::TlsError::InvalidInput {
                message: format!(
                    "--append is only supported for CSV exports; cannot append to {}",
                    path.display()
                ),
            });
        }

        if !path.exists() {
            return Ok(());
        }

        if self.args.output.append {
            return Ok(());
        }

        if self.args.output.overwrite {
            return Ok(());
        }

        Err(crate::TlsError::InvalidInput {
            message: format!(
                "Refusing to overwrite existing file {} without --overwrite or --append",
                path.display()
            ),
        })
    }

    fn append_csv(&self, path: &Path, content: &str) -> Result<()> {
        let existing_len = fs::metadata(path)?.len();
        if existing_len > MAX_APPEND_CSV_BYTES {
            return Err(crate::TlsError::InvalidInput {
                message: format!(
                    "Existing CSV file {} is too large to append safely: {} bytes (max {})",
                    path.display(),
                    existing_len,
                    MAX_APPEND_CSV_BYTES
                ),
            });
        }

        let mut existing = fs::read_to_string(path)?;
        if !existing.ends_with('\n') && !existing.is_empty() {
            existing.push('\n');
        }

        let payload = if existing.trim().is_empty() {
            content.to_string()
        } else {
            let mut lines = content.lines();
            match lines.next() {
                Some(first_line) if !first_line.starts_with("===") => {
                    lines.collect::<Vec<_>>().join("\n")
                }
                _ => content.to_string(),
            }
        };

        if !payload.is_empty() {
            existing.push_str(&payload);
            if !existing.ends_with('\n') {
                existing.push('\n');
            }
        }

        fs::write(path, existing)?;
        Ok(())
    }

    fn bundle_output_path(&self, base: &Path, suffix: &str) -> PathBuf {
        let parent = base.parent();
        let mut derived_name = base
            .file_name()
            .map(|name| name.to_os_string())
            .unwrap_or_else(|| OsString::from("scan"));
        derived_name.push(".");
        derived_name.push(suffix);
        match parent {
            Some(parent) if !parent.as_os_str().is_empty() => parent.join(derived_name),
            _ => PathBuf::from(derived_name),
        }
    }

    fn apply_outprefix_option(&self, path: Option<PathBuf>) -> Result<Option<PathBuf>> {
        path.map(|path| self.apply_outprefix(path)).transpose()
    }

    fn apply_outprefix(&self, path: PathBuf) -> Result<PathBuf> {
        let Some(prefix) = self.args.output.outprefix.as_deref() else {
            return Ok(path);
        };
        validate_outprefix(prefix)?;

        let file_name = path
            .file_name()
            .ok_or_else(|| crate::TlsError::InvalidInput {
                message: format!(
                    "Cannot apply --outprefix to path without file name: {}",
                    path.display()
                ),
            })?;
        let mut prefixed_name = OsString::from(prefix);
        prefixed_name.push(file_name);
        Ok(match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.join(prefixed_name),
            _ => PathBuf::from(prefixed_name),
        })
    }
}

fn validate_outprefix(prefix: &str) -> Result<()> {
    if prefix.contains('/') || prefix.contains('\\') || Path::new(prefix).is_absolute() {
        return Err(crate::TlsError::InvalidInput {
            message: format!(
                "--outprefix must be a filename prefix, not a path: {}",
                prefix
            ),
        });
    }
    Ok(())
}

/// Build a filesystem-safe base filename from a scan target ("host:port").
/// Keeps alphanumerics, '.', '-' and '_'; every other character becomes '_'.
fn sanitize_target_filename(target: &str) -> String {
    let sanitized: String = target
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if sanitized.is_empty() {
        "hello".to_string()
    } else {
        sanitized
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[cfg(unix)]
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    #[test]
    fn test_sanitize_target_filename_replaces_unsafe_chars() {
        assert_eq!(
            sanitize_target_filename("example.com:443"),
            "example.com_443"
        );
        assert_eq!(
            sanitize_target_filename("[2001:db8::1]:443"),
            "_2001_db8__1__443"
        );
    }

    #[test]
    fn test_sanitize_target_filename_empty_falls_back() {
        assert_eq!(sanitize_target_filename(""), "hello");
    }

    #[test]
    fn test_collection_json_output_path_uses_output_all_and_prefix() {
        let temp = tempdir().expect("tempdir should be created");
        let args = Args {
            output: crate::cli::OutputArgs {
                output_all: Some(temp.path().join("report")),
                outprefix: Some("pref-".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        let exporter = ScanExporter::new(&args);
        let path = exporter
            .collection_json_output_path()
            .expect("prefix should be accepted")
            .expect("json path should exist");

        assert_eq!(path, temp.path().join("pref-report.json"));
    }

    #[cfg(unix)]
    #[test]
    fn test_collection_json_output_path_preserves_non_utf8_output_all_filename() {
        let temp = tempdir().expect("tempdir should be created");
        let base_name = OsString::from_vec(vec![b'r', b'e', 0x80, b'p']);
        let args = Args {
            output: crate::cli::OutputArgs {
                output_all: Some(temp.path().join(&base_name)),
                ..Default::default()
            },
            ..Default::default()
        };

        let exporter = ScanExporter::new(&args);
        let path = exporter
            .collection_json_output_path()
            .expect("path should be built")
            .expect("json path should exist");

        let mut expected = base_name;
        expected.push(".json");
        assert_eq!(path.parent(), Some(temp.path()));
        assert_eq!(path.file_name().unwrap().as_bytes(), expected.as_bytes());
    }

    #[cfg(unix)]
    #[test]
    fn test_collection_json_output_path_preserves_non_utf8_filename_with_outprefix() {
        let temp = tempdir().expect("tempdir should be created");
        let file_name = OsString::from_vec(vec![b'r', 0x80, b'.', b'j', b's', b'o', b'n']);
        let args = Args {
            output: crate::cli::OutputArgs {
                json: Some(temp.path().join(&file_name)),
                outprefix: Some("pref-".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        let exporter = ScanExporter::new(&args);
        let path = exporter
            .collection_json_output_path()
            .expect("prefix should be applied")
            .expect("json path should exist");

        let mut expected = OsString::from("pref-");
        expected.push(file_name);
        assert_eq!(path.parent(), Some(temp.path()));
        assert_eq!(path.file_name().unwrap().as_bytes(), expected.as_bytes());
    }

    #[test]
    fn test_collection_json_output_path_rejects_path_outprefix() {
        let temp = tempdir().expect("tempdir should be created");
        let args = Args {
            output: crate::cli::OutputArgs {
                json: Some(temp.path().join("report.json")),
                outprefix: Some("/tmp/pref-".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        let exporter = ScanExporter::new(&args);
        let err = exporter
            .collection_json_output_path()
            .expect_err("absolute outprefix should be rejected");

        assert!(
            err.to_string()
                .contains("--outprefix must be a filename prefix")
        );
    }

    #[test]
    fn test_write_text_file_rejects_existing_file_without_overwrite_or_append() {
        let temp = tempdir().expect("tempdir should be created");
        let path = temp.path().join("report.json");
        fs::write(&path, "{}").expect("seed file should be written");

        let args = Args::default();
        let exporter = ScanExporter::new(&args);
        let err = exporter
            .write_text_file(&path, "{\"ok\":true}", "JSON", ExportKind::Json)
            .expect_err("existing file should be rejected");

        assert!(
            err.to_string()
                .contains("Refusing to overwrite existing file")
        );
    }

    #[test]
    fn test_write_text_file_appends_csv_without_duplicate_header() {
        let temp = tempdir().expect("tempdir should be created");
        let path = temp.path().join("report.csv");
        fs::write(&path, "col1,col2\n1,2\n").expect("seed csv should be written");

        let args = Args {
            output: crate::cli::OutputArgs {
                append: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let exporter = ScanExporter::new(&args);
        exporter
            .write_text_file(&path, "col1,col2\n3,4\n", "CSV", ExportKind::Csv)
            .expect("csv append should succeed");

        let content = fs::read_to_string(&path).expect("csv should be readable");
        assert_eq!(content, "col1,col2\n1,2\n3,4\n");
    }

    #[test]
    fn test_write_text_file_rejects_append_for_non_csv_even_when_new() {
        let temp = tempdir().expect("tempdir should be created");
        let path = temp.path().join("report.json");

        let args = Args {
            output: crate::cli::OutputArgs {
                append: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let exporter = ScanExporter::new(&args);
        let err = exporter
            .write_text_file(&path, "{}", "JSON", ExportKind::Json)
            .expect_err("append must be CSV-only");

        assert!(
            err.to_string()
                .contains("--append is only supported for CSV")
        );
        assert!(!path.exists());
    }

    #[test]
    fn test_write_text_file_rejects_oversized_existing_csv_before_append() {
        let temp = tempdir().expect("tempdir should be created");
        let path = temp.path().join("report.csv");
        let file = fs::File::create(&path).expect("seed csv should be created");
        file.set_len(MAX_APPEND_CSV_BYTES + 1)
            .expect("seed csv should be oversized");

        let args = Args {
            output: crate::cli::OutputArgs {
                append: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let exporter = ScanExporter::new(&args);
        let err = exporter
            .write_text_file(&path, "col1,col2\n3,4\n", "CSV", ExportKind::Csv)
            .expect_err("oversized CSV append should fail before reading");

        assert!(err.to_string().contains("too large to append safely"));
    }

    #[test]
    fn test_write_text_file_appends_sectioned_csv_without_dropping_marker() {
        let temp = tempdir().expect("tempdir should be created");
        let path = temp.path().join("report.csv");
        fs::write(&path, "=== SCAN SUMMARY ===\nTarget\nold\n")
            .expect("seed csv should be written");

        let args = Args {
            output: crate::cli::OutputArgs {
                append: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let exporter = ScanExporter::new(&args);
        exporter
            .write_text_file(
                &path,
                "=== SCAN SUMMARY ===\nTarget\nnew\n",
                "CSV",
                ExportKind::Csv,
            )
            .expect("sectioned csv append should succeed");

        let content = fs::read_to_string(&path).expect("csv should be readable");
        assert_eq!(
            content,
            "=== SCAN SUMMARY ===\nTarget\nold\n=== SCAN SUMMARY ===\nTarget\nnew\n"
        );
    }

    #[test]
    fn test_export_hellos_rejects_existing_file_without_overwrite() {
        let target = format!("cipherrun-export-hello-test-{}:443", std::process::id());
        let path = PathBuf::from(format!(
            "{}.client_hello.hex",
            sanitize_target_filename(&target)
        ));
        let _ = fs::remove_file(&path);
        fs::write(&path, "existing").expect("seed hello export");

        let args = Args {
            fingerprint: crate::cli::FingerprintArgs {
                export_hello: Some("hex".to_string()),
                ..Default::default()
            },
            output: crate::cli::OutputArgs {
                quiet: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut results = crate::scanner::ScanResults {
            target,
            ..Default::default()
        };
        results.fingerprints_mut().client_hello_raw = Some(vec![0x16, 0x03, 0x01]);

        let exporter = ScanExporter::new(&args);
        let err = exporter
            .export_hellos(&results)
            .expect_err("existing hello export should be rejected");

        assert!(
            err.to_string()
                .contains("Refusing to overwrite existing file")
        );
        assert_eq!(
            fs::read_to_string(&path).expect("read seeded file"),
            "existing"
        );
        let _ = fs::remove_file(path);
    }
}
