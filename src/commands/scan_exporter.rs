use crate::application::ScanExportView;
use crate::{Args, Result};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExportKind {
    Json,
    MultiIpJson,
    Csv,
    Html,
    Xml,
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

    pub fn build_plan_from_view<'b>(&self, view: ScanExportView<'b>) -> ScanExportPlan<'b> {
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

        ScanExportPlan {
            results: view.results(),
            json_file: json_file.map(|path| self.apply_outprefix(path)),
            json_pretty: self.args.output.json_pretty,
            json_multi_ip: json_multi_ip.map(|path| self.apply_outprefix(path)),
            csv_file: csv_file.map(|path| self.apply_outprefix(path)),
            html_file: html_file.map(|path| self.apply_outprefix(path)),
            xml_file: xml_file.map(|path| self.apply_outprefix(path)),
        }
    }

    pub(crate) fn collection_json_output_path(&self) -> Option<PathBuf> {
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
            let csv = plan.results.to_csv()?;
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
                ExportKind::Json | ExportKind::MultiIpJson | ExportKind::Html | ExportKind::Xml => {
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
        if !path.exists() {
            return Ok(());
        }

        if self.args.output.append {
            if matches!(kind, ExportKind::Csv) {
                return Ok(());
            }
            return Err(crate::TlsError::InvalidInput {
                message: format!(
                    "--append is only supported for CSV exports; cannot append to {}",
                    path.display()
                ),
            });
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
        let mut existing = fs::read_to_string(path)?;
        if !existing.ends_with('\n') && !existing.is_empty() {
            existing.push('\n');
        }

        let payload = if existing.trim().is_empty() {
            content.to_string()
        } else {
            let mut lines = content.lines();
            let _header = lines.next();
            lines.collect::<Vec<_>>().join("\n")
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
        let file_name = base
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| "scan".to_string());
        let derived_name = format!("{}.{}", file_name, suffix);
        match parent {
            Some(parent) if !parent.as_os_str().is_empty() => parent.join(derived_name),
            _ => PathBuf::from(derived_name),
        }
    }

    fn apply_outprefix(&self, path: PathBuf) -> PathBuf {
        let Some(prefix) = self.args.output.outprefix.as_deref() else {
            return path;
        };

        let file_name = path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_default();
        let prefixed_name = format!("{}{}", prefix, file_name);
        match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.join(prefixed_name),
            _ => PathBuf::from(prefixed_name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

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
            .expect("json path should exist");

        assert_eq!(path, temp.path().join("pref-report.json"));
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
}
