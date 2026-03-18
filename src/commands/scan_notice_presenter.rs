pub struct ScanNoticePresenter;

impl ScanNoticePresenter {
    pub fn new() -> Self {
        Self
    }

    pub fn render_storage_notice(&self, stored_scan_id: Option<i64>) {
        if let Some(scan_id) = stored_scan_id {
            println!("\n✓ Scan results stored in database (scan_id: {})", scan_id);
        }
    }

    pub fn render_export_spacing(&self, exported: bool) {
        if exported {
            println!();
        }
    }
}
