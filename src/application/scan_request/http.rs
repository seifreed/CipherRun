#[derive(Debug, Clone, Default)]
pub struct ScanRequestHttp {
    pub custom_headers: Vec<String>,
    pub sneaky: bool,
    /// Custom User-Agent string (`--user-agent`). Overrides the default and the
    /// sneaky-mode user agent when set.
    pub user_agent: Option<String>,
    /// HTTP Basic Authentication credentials in `user:password` form
    /// (`--basicauth`), sent as an `Authorization: Basic` header.
    pub basicauth: Option<String>,
}
