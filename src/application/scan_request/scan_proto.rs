#[derive(Debug, Clone, Default)]
pub struct ScanRequestProto {
    /// Test all protocol versions (was `protocols` field)
    pub enabled: bool,
    pub ssl2: bool,
    pub ssl3: bool,
    pub tls10: bool,
    pub tls11: bool,
    pub tls12: bool,
    pub tls13: bool,
    pub tlsall: bool,
}
