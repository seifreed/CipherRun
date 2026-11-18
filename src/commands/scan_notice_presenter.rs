pub struct ScanNoticePresenter;

impl ScanNoticePresenter {
    pub(super) fn new() -> Self {
        Self
    }

    pub(super) fn render_storage_notice(&self, stored_scan_id: Option<i64>) {
        if let Some(scan_id) = stored_scan_id {
            println!("\n✓ Scan results stored in database (scan_id: {})", scan_id);
        }
    }

    pub(super) fn render_export_spacing(&self, exported: bool) {
        if exported {
            println!();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ScanNoticePresenter;

    #[test]
    fn storage_notice_is_rendered_only_when_scan_was_stored() {
        let presenter = ScanNoticePresenter::new();
        presenter.render_storage_notice(None);
        presenter.render_storage_notice(Some(42));
    }

    #[test]
    fn export_spacing_is_rendered_only_after_an_export() {
        let presenter = ScanNoticePresenter::new();
        presenter.render_export_spacing(false);
        presenter.render_export_spacing(true);
    }
}
