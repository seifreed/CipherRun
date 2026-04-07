#[derive(Debug, Clone, Default)]
pub struct ScanRequestHttp {
    pub custom_headers: Vec<String>,
    pub sneaky: bool,
}
