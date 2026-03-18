use crate::application::ScanExportView;
use crate::{Args, Result};

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
        ScanExportPlan {
            results: view.results(),
            json_file: self.args.output.json.clone(),
            json_pretty: self.args.output.json_pretty,
            json_multi_ip: if view.has_multi_ip_export_data() {
                self.args.output.json_multi_ip.clone()
            } else {
                None
            },
            csv_file: self.args.output.csv.clone(),
            html_file: self.args.output.html.clone(),
            xml_file: self.args.output.xml.clone(),
        }
    }

    pub fn export(&self, plan: ScanExportPlan<'_>) -> Result<ScanExportOutcome> {
        if !plan.has_export_targets() {
            return Ok(ScanExportOutcome::none());
        }

        let has_multi_ip_json_target = plan.has_multi_ip_json_target();
        let mut exported = false;
        if let Some(json_file) = plan.json_file {
            let json = plan.results.to_json(plan.json_pretty)?;
            std::fs::write(&json_file, &json)?;
            println!("✓ Results exported to JSON: {}", json_file.display());
            exported = true;
        }

        if has_multi_ip_json_target
            && let Some(json_path) = plan.json_multi_ip
            && let Some(ref report) = plan.results.multi_ip_report
        {
            use crate::output::json::generate_multi_ip_json;
            let json = generate_multi_ip_json(report, plan.json_pretty)?;
            std::fs::write(&json_path, &json)?;
            println!(
                "✓ Multi-IP report exported to JSON: {}",
                json_path.display()
            );
            exported = true;
        }

        if let Some(csv_file) = plan.csv_file {
            let csv = plan.results.to_csv()?;
            std::fs::write(&csv_file, &csv)?;
            println!("✓ Results exported to CSV: {}", csv_file.display());
            exported = true;
        }

        if let Some(html_file) = plan.html_file {
            use crate::output::html;
            let html_content = html::generate_html_report(plan.results)?;
            std::fs::write(&html_file, &html_content)?;
            println!("✓ Results exported to HTML: {}", html_file.display());
            exported = true;
        }

        if let Some(xml_file) = plan.xml_file {
            use crate::output::xml;
            let xml_content = xml::generate_xml_report(plan.results)?;
            std::fs::write(&xml_file, &xml_content)?;
            println!("✓ Results exported to XML: {}", xml_file.display());
            exported = true;
        }

        Ok(ScanExportOutcome { exported })
    }
}
