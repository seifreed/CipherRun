/// Outcome of probing a server for support of a single cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CipherProbeStatus {
    /// Server returned a ServerHello: the suite is supported.
    Supported,
    /// Server returned a TLS alert: the suite was conclusively rejected.
    NotSupported,
    /// No conclusive answer: no socket, transport error, truncated/non-TLS
    /// response. Never treated as a clean pass.
    Inconclusive,
}

#[derive(Clone, Copy)]
pub(crate) struct CipherProbeOptions<'a> {
    pub(crate) starttls: Option<crate::starttls::StarttlsProtocol>,
    pub(crate) sni_override: Option<&'a str>,
    pub(crate) starttls_hostname: Option<&'a str>,
    pub(crate) starttls_server_mode: bool,
    pub(crate) test_all_ips: bool,
}
