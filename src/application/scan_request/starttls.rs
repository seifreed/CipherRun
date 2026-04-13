#[derive(Debug, Clone, Default)]
pub struct ScanRequestStarttls {
    pub protocol: Option<String>,
    pub smtp: bool,
    pub imap: bool,
    pub pop3: bool,
    pub ftp: bool,
    pub ldap: bool,
    pub xmpp: bool,
    pub psql: bool,
    pub mysql: bool,
    pub irc: bool,
    pub xmpp_server: bool,
    pub rdp: bool,
    pub nntp: bool,
    pub sieve: bool,
    pub lmtp: bool,
}
