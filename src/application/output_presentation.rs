#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputPresentationMode {
    #[default]
    Normal,
    DnsOnly,
    ResponseOnly,
}

impl OutputPresentationMode {
    pub fn is_dns_only(self) -> bool {
        matches!(self, Self::DnsOnly)
    }

    pub fn is_response_only(self) -> bool {
        matches!(self, Self::ResponseOnly)
    }
}
