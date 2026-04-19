#[derive(Debug, Clone, Default)]
pub struct ScanRequestPrefs {
    pub fast: bool,
    pub disable_rating: bool,
    pub pre_handshake: bool,
    pub probe_status: bool,
    pub headers: bool,
}
