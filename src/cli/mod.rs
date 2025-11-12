// CLI module - Command line interface and argument parsing

use clap::{ArgAction, Parser};
use std::path::PathBuf;

#[derive(Parser, Debug, Clone, Default)]
#[command(author, version, about, long_about = None)]
#[command(name = "cipherrun")]
#[command(about = "Fast, modular TLS/SSL security scanner", long_about = None)]
pub struct Args {
    /// Target URI (host:port or URL)
    #[arg(value_name = "URI")]
    pub target: Option<String>,

    /// Input file with multiple targets
    #[arg(short = 'f', long = "file", value_name = "FILE")]
    pub input_file: Option<PathBuf>,

    /// Test MX records for a domain (mail servers)
    #[arg(long = "mx", value_name = "DOMAIN")]
    pub mx_domain: Option<String>,

    /// STARTTLS protocol (smtp, imap, pop3, ftp, xmpp, etc.)
    #[arg(short = 't', long = "starttls", value_name = "PROTOCOL")]
    pub starttls: Option<String>,

    /// Test all protocols
    #[arg(short = 'p', long = "protocols")]
    pub protocols: bool,

    /// Test all ciphers
    #[arg(short = 'e', long = "each-cipher")]
    pub each_cipher: bool,

    /// Test ciphers per protocol
    #[arg(short = 'E', long = "cipher-per-proto")]
    pub cipher_per_proto: bool,

    /// Test standard cipher categories
    #[arg(short = 's', long = "std")]
    pub categories: bool,

    /// Test forward secrecy
    #[arg(short = 'F', long = "fs")]
    pub forward_secrecy: bool,

    /// Test server defaults
    #[arg(short = 'S', long = "server-defaults")]
    pub server_defaults: bool,

    /// Test server cipher preference
    #[arg(short = 'P', long = "server-preference")]
    pub server_preference: bool,

    /// Test HTTP headers
    #[arg(short = 'h', long = "headers")]
    pub headers: bool,

    /// Test all vulnerabilities
    #[arg(short = 'U', long = "vulnerable")]
    pub vulnerabilities: bool,

    /// Test for Heartbleed
    #[arg(short = 'H', long = "heartbleed")]
    pub heartbleed: bool,

    /// Test for CCS Injection
    #[arg(short = 'I', long = "ccs")]
    pub ccs: bool,

    /// Test for Ticketbleed
    #[arg(short = 'T', long = "ticketbleed")]
    pub ticketbleed: bool,

    /// Test for ROBOT
    #[arg(long = "robot")]
    pub robot: bool,

    /// Test for renegotiation vulnerabilities
    #[arg(short = 'R', long = "renegotiation")]
    pub renegotiation: bool,

    /// Test for CRIME
    #[arg(short = 'C', long = "crime")]
    pub crime: bool,

    /// Test for BREACH
    #[arg(short = 'B', long = "breach")]
    pub breach: bool,

    /// Test for POODLE
    #[arg(short = 'O', long = "poodle")]
    pub poodle: bool,

    /// Test for TLS_FALLBACK_SCSV
    #[arg(short = 'Z', long = "tls-fallback")]
    pub fallback: bool,

    /// Test for SWEET32
    #[arg(short = 'W', long = "sweet32")]
    pub sweet32: bool,

    /// Test for BEAST
    #[arg(short = 'A', long = "beast")]
    pub beast: bool,

    /// Test for LUCKY13
    #[arg(short = 'L', long = "lucky13")]
    pub lucky13: bool,

    /// Test for FREAK
    #[arg(long = "freak")]
    pub freak: bool,

    /// Test for LOGJAM
    #[arg(short = 'J', long = "logjam")]
    pub logjam: bool,

    /// Test for DROWN
    #[arg(short = 'D', long = "drown")]
    pub drown: bool,

    /// Test for 0-RTT / Early Data replay attacks (TLS 1.3)
    #[arg(long = "early-data")]
    pub early_data: bool,

    /// Test client simulations
    #[arg(short = 'c', long = "client-simulation")]
    pub client_simulation: bool,

    /// Run full test suite
    #[arg(short = '9', long = "full")]
    pub full: bool,

    /// Quiet mode (no banner)
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,

    /// Wide output
    #[arg(long = "wide")]
    pub wide: bool,

    /// Color output mode (0-3)
    #[arg(long = "color", value_name = "MODE", default_value = "2")]
    pub color: u8,

    /// Output to JSON file
    #[arg(long = "json", value_name = "FILE")]
    pub json: Option<PathBuf>,

    /// Pretty print JSON output
    #[arg(long = "json-pretty")]
    pub json_pretty: bool,

    /// Output to CSV file
    #[arg(long = "csv", value_name = "FILE")]
    pub csv: Option<PathBuf>,

    /// Output to HTML file
    #[arg(long = "html", value_name = "FILE")]
    pub html: Option<PathBuf>,

    /// Run all tests (default: enabled, use --all=false to disable)
    #[arg(short = 'a', long = "all", default_value_t = true, action = ArgAction::Set)]
    pub all: bool,

    /// Port to test
    #[arg(long = "port", value_name = "PORT")]
    pub port: Option<u16>,

    /// Log file
    #[arg(long = "logfile", value_name = "FILE")]
    pub logfile: Option<PathBuf>,

    /// Parallel testing mode
    #[arg(long = "parallel")]
    pub parallel: bool,

    /// Maximum parallel connections
    #[arg(long = "max-parallel", value_name = "NUM", default_value = "20")]
    pub max_parallel: usize,

    /// Maximum concurrent cipher tests per protocol (default: 10)
    /// Lower values reduce network load and prevent "Network is down" errors
    #[arg(long = "max-concurrent-ciphers", value_name = "NUM", default_value = "10")]
    pub max_concurrent_ciphers: usize,

    /// Socket timeout in seconds
    #[arg(long = "socket-timeout", value_name = "SECONDS")]
    pub socket_timeout: Option<u64>,

    /// OpenSSL binary path
    #[arg(long = "openssl", value_name = "PATH")]
    pub openssl_path: Option<PathBuf>,

    /// Use only IPv4
    #[arg(short = '4')]
    pub ipv4_only: bool,

    /// Use only IPv6
    #[arg(short = '6')]
    pub ipv6_only: bool,

    /// Specific IP to test
    #[arg(long = "ip", value_name = "IP")]
    pub ip: Option<String>,

    /// Proxy (host:port)
    #[arg(long = "proxy", value_name = "HOST:PORT")]
    pub proxy: Option<String>,

    /// HTTP Basic Authentication (user:password)
    #[arg(long = "basicauth", value_name = "USER:PASS")]
    pub basicauth: Option<String>,

    /// Custom User-Agent string
    #[arg(long = "user-agent", value_name = "STRING")]
    pub user_agent: Option<String>,

    /// IDS-friendly mode (slower, avoid triggering IDS/IPS)
    #[arg(long = "ids-friendly")]
    pub ids_friendly: bool,

    /// Show hints for findings
    #[arg(long = "hints")]
    pub hints: bool,

    /// Filter findings by minimum severity (low, medium, high, critical)
    #[arg(long = "severity", value_name = "LEVEL")]
    pub severity: Option<String>,

    /// Enable phone-out (CRL, OCSP checks)
    #[arg(long = "phone-out")]
    pub phone_out: bool,

    /// Additional CA file or directory
    #[arg(long = "add-ca", value_name = "PATH")]
    pub add_ca: Option<PathBuf>,

    /// Client certificate for mTLS (PEM file with cert and unencrypted key)
    #[arg(long = "mtls", value_name = "FILE")]
    pub mtls_cert: Option<PathBuf>,

    /// Custom HTTP request headers (can be specified multiple times)
    #[arg(long = "reqheader", value_name = "HEADER")]
    pub custom_headers: Vec<String>,

    /// Sneaky mode - leave less traces in target logs
    #[arg(long = "sneaky")]
    pub sneaky: bool,

    /// Show RFC/IANA cipher names instead of OpenSSL names
    #[arg(long = "mapping", value_name = "no-openssl|no-rfc")]
    pub cipher_mapping: Option<String>,

    /// Show each cipher tested (not just supported ones)
    #[arg(long = "show-each")]
    pub show_each: bool,

    /// Colorblind mode (adjust colors for accessibility)
    #[arg(long = "colorblind")]
    pub colorblind: bool,

    /// Verbose level (0-6)
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,

    // ============ NEW: Missing CLI Options ============
    /// XMPP host domain (for STARTTLS XMPP)
    #[arg(long = "xmpphost", value_name = "DOMAIN")]
    pub xmpphost: Option<String>,

    /// OpenSSL timeout in seconds
    #[arg(long = "openssl-timeout", value_name = "SECONDS")]
    pub openssl_timeout: Option<u64>,

    /// Use OpenSSL native instead of sockets
    #[arg(long = "ssl-native")]
    pub ssl_native: bool,

    /// Enable OpenSSL bugs workarounds
    #[arg(long = "bugs")]
    pub bugs: bool,

    /// Assume HTTP protocol when detection fails
    #[arg(long = "assume-http")]
    pub assume_http: bool,

    /// Warning control mode (batch, off, or default)
    #[arg(long = "warnings", value_name = "MODE")]
    pub warnings: Option<String>,

    /// Fast mode - skip some tests for speed
    #[arg(long = "fast")]
    pub fast: bool,

    /// List local OpenSSL ciphers and exit
    #[arg(long = "local")]
    pub local: bool,

    /// Append to output files instead of overwriting
    #[arg(long = "append")]
    pub append: bool,

    /// Overwrite output files without prompting
    #[arg(long = "overwrite")]
    pub overwrite: bool,

    /// Prefix for output filenames
    #[arg(long = "outprefix", value_name = "PREFIX")]
    pub outprefix: Option<String>,

    /// Disable SSL Labs rating
    #[arg(long = "disable-rating")]
    pub disable_rating: bool,

    /// Output all formats with basename (like nmap -oA)
    #[arg(short = 'o', long = "output-all", value_name = "BASENAME")]
    pub output_all: Option<PathBuf>,

    // ============ NEW: sslscan parity features ============
    /// Sleep between connection requests in milliseconds
    #[arg(long = "sleep", value_name = "MSEC")]
    pub sleep: Option<u64>,

    /// Connection timeout in seconds (separate from socket timeout)
    #[arg(long = "connect-timeout", value_name = "SECONDS")]
    pub connect_timeout: Option<u64>,

    /// Show handshake times in milliseconds
    #[arg(long = "show-times")]
    pub show_times: bool,

    /// RDP mode - send RDP preamble before TLS handshake
    #[arg(long = "rdp")]
    pub rdp: bool,

    /// Enumerate server signature algorithms
    #[arg(long = "show-sigs")]
    pub show_sigs: bool,

    /// Enumerate key exchange groups (curves, DH groups)
    #[arg(long = "show-groups")]
    pub show_groups: bool,

    /// Show list of CAs acceptable for client certificates
    #[arg(long = "show-client-cas")]
    pub show_client_cas: bool,

    /// Client private key file for mTLS
    #[arg(long = "pk", value_name = "FILE")]
    pub client_key: Option<PathBuf>,

    /// Password for client private key
    #[arg(long = "pkpass", value_name = "PASSWORD")]
    pub client_key_password: Option<String>,

    /// Client certificate file for mTLS (can be different from --pk)
    #[arg(long = "certs", value_name = "FILE")]
    pub client_certs: Option<PathBuf>,

    /// Output to XML file
    #[arg(long = "xml", value_name = "FILE")]
    pub xml: Option<PathBuf>,

    // ============ NEW: Additional sslscan parity features ============
    /// STARTTLS for SMTP (ports 25, 587, 465)
    #[arg(long = "starttls-smtp")]
    pub starttls_smtp: bool,

    /// STARTTLS for IMAP (port 143)
    #[arg(long = "starttls-imap")]
    pub starttls_imap: bool,

    /// STARTTLS for POP3 (port 110)
    #[arg(long = "starttls-pop3")]
    pub starttls_pop3: bool,

    /// STARTTLS for FTP (port 21)
    #[arg(long = "starttls-ftp")]
    pub starttls_ftp: bool,

    /// STARTTLS for LDAP (port 389)
    #[arg(long = "starttls-ldap")]
    pub starttls_ldap: bool,

    /// STARTTLS for XMPP/Jabber (port 5222)
    #[arg(long = "starttls-xmpp")]
    pub starttls_xmpp: bool,

    /// STARTTLS for PostgreSQL (port 5432)
    #[arg(long = "starttls-psql")]
    pub starttls_psql: bool,

    /// STARTTLS for MySQL (port 3306)
    #[arg(long = "starttls-mysql")]
    pub starttls_mysql: bool,

    /// STARTTLS for IRC (port 6667)
    #[arg(long = "starttls-irc")]
    pub starttls_irc: bool,

    /// XMPP server-to-server mode (alternative to --starttls-xmpp)
    #[arg(long = "xmpp-server")]
    pub xmpp_server: bool,

    /// Use IANA/RFC cipher names instead of OpenSSL names
    #[arg(long = "iana-names")]
    pub iana_names: bool,

    /// Show hexadecimal cipher IDs
    #[arg(long = "show-cipher-ids")]
    pub show_cipher_ids: bool,

    /// List all ciphers supported by CipherRun and exit
    #[arg(long = "show-ciphers")]
    pub show_ciphers: bool,

    /// Show the full certificate chain (not just leaf)
    #[arg(long = "show-certificates")]
    pub show_certificates: bool,

    /// Skip cipher suite enumeration (faster, only protocols + vulnerabilities)
    #[arg(long = "no-ciphersuites")]
    pub no_ciphersuites: bool,

    /// Skip TLS Fallback SCSV check
    #[arg(long = "no-fallback")]
    pub no_fallback: bool,

    /// Hide EC curve names and DHE key lengths
    #[arg(long = "no-cipher-details")]
    pub no_cipher_details: bool,

    /// Display OCSP stapling status
    #[arg(long = "ocsp")]
    pub ocsp: bool,

    /// Display version information and exit
    #[arg(long = "version", short = 'V')]
    pub version: bool,

    /// Disable colored output (alias for --color 0)
    #[arg(long = "no-colour")]
    pub no_colour: bool,

    /// Disable colored output (US spelling, alias for --color 0)
    #[arg(long = "no-color")]
    pub no_color: bool,

    /// Custom SNI hostname (for CDN/vhost testing)
    #[arg(long = "sni-name", value_name = "NAME")]
    pub sni_name: Option<String>,

    /// Test only SSLv2
    #[arg(long = "ssl2")]
    pub ssl2: bool,

    /// Test only SSLv3
    #[arg(long = "ssl3")]
    pub ssl3: bool,

    /// Test only TLS 1.0
    #[arg(long = "tls10")]
    pub tls10: bool,

    /// Test only TLS 1.1
    #[arg(long = "tls11")]
    pub tls11: bool,

    /// Test only TLS 1.2
    #[arg(long = "tls12")]
    pub tls12: bool,

    /// Test only TLS 1.3
    #[arg(long = "tls13")]
    pub tls13: bool,

    /// Test all TLS protocols (skip SSLv2/SSLv3)
    #[arg(long = "tlsall")]
    pub tlsall: bool,

    /// Skip key exchange groups enumeration
    #[arg(long = "no-groups")]
    pub no_groups: bool,

    /// Skip TLS compression check (CRIME)
    #[arg(long = "no-compression")]
    pub no_compression: bool,

    /// Skip Heartbleed vulnerability check
    #[arg(long = "no-heartbleed")]
    pub no_heartbleed: bool,

    /// Skip renegotiation vulnerability check
    #[arg(long = "no-renegotiation")]
    pub no_renegotiation: bool,

    /// Skip certificate validation warnings
    #[arg(long = "no-check-certificate")]
    pub no_check_certificate: bool,

    /// Test all IP addresses resolved for hostname (default behavior when multiple IPs found)
    /// When a hostname resolves to multiple IPs (load balancers, Anycast), all IPs are tested
    /// by default and results are aggregated using worst-case approach. Use --first-ip-only
    /// to scan only the first IP for faster results.
    #[arg(long = "test-all-ips")]
    pub test_all_ips: bool,

    /// Scan only the first resolved IP address (faster, single IP mode)
    /// Use this flag to explicitly scan only the first IP when you want faster results,
    /// especially for hosts with multiple load balancer IPs. By default, all IPs are scanned.
    #[arg(long = "first-ip-only")]
    pub first_ip_only: bool,

    // ============ Retry Configuration ============
    /// Maximum number of retries for transient network failures (0 = no retries)
    /// Helps distinguish between permanent failures (connection refused) and
    /// transient failures (timeouts, connection resets)
    #[arg(long = "max-retries", value_name = "COUNT", default_value = "3")]
    pub max_retries: usize,

    /// Initial backoff duration in milliseconds for retry logic
    /// Backoff doubles with each retry (exponential backoff) up to max-backoff
    #[arg(long = "retry-backoff", value_name = "MSEC", default_value = "100")]
    pub retry_backoff_ms: u64,

    /// Maximum backoff duration in milliseconds for retry logic
    /// Prevents excessive delays during multiple retries
    #[arg(long = "max-backoff", value_name = "MSEC", default_value = "5000")]
    pub max_backoff_ms: u64,

    /// Disable retry logic (fail immediately on first error)
    /// Equivalent to --max-retries 0
    #[arg(long = "no-retry")]
    pub no_retry: bool,

    // ============ Database Persistence ============
    /// Database configuration file (TOML format)
    #[arg(long = "db-config", value_name = "FILE")]
    pub db_config: Option<PathBuf>,

    /// Store scan results in database
    #[arg(long = "store")]
    pub store_results: bool,

    /// Query scan history for target (hostname:port)
    #[arg(long = "history", value_name = "HOSTNAME:PORT")]
    pub history: Option<String>,

    /// Limit for history results
    #[arg(long = "history-limit", value_name = "COUNT", default_value = "10")]
    pub history_limit: i64,

    /// Cleanup old scans (delete scans older than N days)
    #[arg(long = "cleanup-days", value_name = "DAYS")]
    pub cleanup_days: Option<i64>,

    /// Initialize database (create tables and run migrations)
    #[arg(long = "db-init")]
    pub db_init: bool,

    /// Generate example database configuration file
    #[arg(long = "db-config-example", value_name = "FILE")]
    pub db_config_example: Option<PathBuf>,

    // ============ Certificate Monitoring ============
    /// Start the monitoring daemon
    #[arg(long = "monitor")]
    pub monitor: bool,

    /// Monitoring configuration file (TOML format)
    #[arg(long = "monitor-config", value_name = "FILE")]
    pub monitor_config: Option<PathBuf>,

    /// File with domains to monitor (one per line, host:port format)
    #[arg(long = "monitor-domains", value_name = "FILE")]
    pub monitor_domains: Option<PathBuf>,

    /// Single domain to monitor (host:port format)
    #[arg(long = "monitor-domain", value_name = "HOST:PORT")]
    pub monitor_domain: Option<String>,

    /// Test alert channels (send test alert to all configured channels)
    #[arg(long = "test-alert")]
    pub test_alert: bool,

    // ============ Policy-as-Code Engine ============
    /// Policy file to enforce (YAML format)
    #[arg(long = "policy", value_name = "FILE")]
    pub policy: Option<PathBuf>,

    /// Exit with non-zero code if policy violations found (for CI/CD)
    #[arg(long = "enforce")]
    pub enforce: bool,

    /// Policy output format (terminal, json, csv)
    #[arg(
        long = "policy-format",
        value_name = "FORMAT",
        default_value = "terminal"
    )]
    pub policy_format: String,

    // ============ Compliance Framework Engine ============
    /// Compliance framework to evaluate against (pci-dss-v4, nist-sp800-52r2, hipaa, soc2, mozilla-modern, mozilla-intermediate, gdpr)
    #[arg(long = "compliance", value_name = "FRAMEWORK")]
    pub compliance: Option<String>,

    /// Compliance report output format (terminal, json, csv, html)
    #[arg(
        long = "compliance-format",
        value_name = "FORMAT",
        default_value = "terminal"
    )]
    pub compliance_format: String,

    /// List available compliance frameworks and exit
    #[arg(long = "list-compliance")]
    pub list_compliance: bool,

    // ============ REST API Server ============
    /// Start REST API server mode
    #[arg(long = "serve")]
    pub serve: bool,

    /// API server host address
    #[arg(long = "api-host", value_name = "HOST", default_value = "0.0.0.0")]
    pub api_host: String,

    /// API server port
    #[arg(long = "api-port", value_name = "PORT", default_value = "8080")]
    pub api_port: u16,

    /// API configuration file (TOML format)
    #[arg(long = "api-config", value_name = "FILE")]
    pub api_config: Option<PathBuf>,

    /// Maximum concurrent scans
    #[arg(long = "api-max-concurrent", value_name = "NUM", default_value = "10")]
    pub api_max_concurrent: usize,

    /// Enable Swagger UI documentation
    #[arg(long = "api-swagger")]
    pub api_swagger: bool,

    /// Generate example API configuration file
    #[arg(long = "api-config-example", value_name = "FILE")]
    pub api_config_example: Option<PathBuf>,

    // ============ Database Analytics ============
    /// Compare two scans (format: SCAN_ID_1:SCAN_ID_2)
    #[arg(long = "compare", value_name = "SCAN_ID_1:SCAN_ID_2")]
    pub compare: Option<String>,

    /// Detect changes for hostname in last N days (format: HOSTNAME:PORT:DAYS)
    #[arg(long = "changes", value_name = "HOSTNAME:PORT:DAYS")]
    pub changes: Option<String>,

    /// Analyze trends for hostname in last N days (format: HOSTNAME:PORT:DAYS)
    #[arg(long = "trends", value_name = "HOSTNAME:PORT:DAYS")]
    pub trends: Option<String>,

    /// Generate dashboard data for hostname (format: HOSTNAME:PORT:DAYS)
    #[arg(long = "dashboard", value_name = "HOSTNAME:PORT:DAYS")]
    pub dashboard: Option<String>,

    // ============ HIGH PRIORITY Features (4-10) ============
    /// Use pre-handshake mode for fast certificate retrieval (early termination)
    /// Disconnects after ServerHello without completing full handshake (2-3x faster)
    /// Only works with TLS 1.0-1.2
    #[arg(long = "pre-handshake", alias = "ps")]
    pub pre_handshake: bool,

    /// Scan all resolved IP addresses for hostname (Anycast detection)
    /// Tests each A and AAAA record individually to detect Anycast deployments
    #[arg(long = "scan-all-ips", alias = "sa")]
    pub scan_all_ips: bool,

    /// Use random SNI when scanning IP addresses
    /// Generates random valid-looking SNI hostnames
    #[arg(long = "random-sni", alias = "rs")]
    pub random_sni: bool,

    /// Use reverse PTR lookup for SNI when scanning IPs
    /// Performs reverse DNS to determine appropriate SNI
    #[arg(long = "reverse-ptr-sni", alias = "rps")]
    pub reverse_ptr_sni: bool,

    /// Show probe status (success/failure) for each target
    /// Displays connection status with timing information
    #[arg(long = "probe-status", alias = "tps")]
    pub probe_status: bool,

    /// Export Client/Server Hello raw data in specified format
    /// Valid formats: hex, base64, hexdump, binary
    #[arg(long = "export-hello", value_name = "FORMAT")]
    pub export_hello: Option<String>,

    // ============ MEDIUM PRIORITY Features (11-15) ============
    /// Output only unique domain names from certificates
    #[arg(long = "dns", alias = "dns-only")]
    pub dns_only: bool,

    /// Output response data only (no host:port prefix)
    #[arg(long = "response-only", alias = "ro")]
    pub response_only: bool,

    /// Custom DNS resolvers (comma-separated: 8.8.8.8,1.1.1.1)
    #[arg(long = "resolvers", value_delimiter = ',')]
    pub resolvers: Vec<String>,

    /// Delay between connections (e.g "200ms", "1s")
    #[arg(long = "delay")]
    pub delay: Option<String>,

    /// Hard fail on revocation check errors (requires --phone-out)
    #[arg(long = "hardfail", alias = "hf")]
    pub hardfail: bool,

    // ============ Certificate Transparency Logs Streaming ============
    /// Enable Certificate Transparency logs streaming mode
    #[arg(long = "ct-logs", alias = "ctl")]
    pub ct_logs: bool,

    /// Start from beginning of CT logs (index 0)
    #[arg(long = "ct-beginning", alias = "cb", requires = "ct_logs")]
    pub ct_beginning: bool,

    /// Start from custom index per log (format: sourceID=index)
    #[arg(
        long = "ct-index",
        alias = "cti",
        requires = "ct_logs",
        value_name = "SOURCE=INDEX"
    )]
    pub ct_index: Vec<String>,

    /// CT logs poll interval in seconds (default: 60)
    #[arg(long = "ct-poll-interval", requires = "ct_logs", default_value = "60")]
    pub ct_poll_interval: u64,

    /// CT logs batch size (default: 1000, max: 1000)
    #[arg(long = "ct-batch-size", requires = "ct_logs", default_value = "1000")]
    pub ct_batch_size: u64,

    /// Output CT log entries as JSON (one per line)
    #[arg(long = "ct-json", requires = "ct_logs")]
    pub ct_json: bool,

    /// Silent mode for CT logs (no stats output, only certificates)
    #[arg(long = "ct-silent", requires = "ct_logs")]
    pub ct_silent: bool,

    // ============ JA3 TLS Client Fingerprinting ============
    /// Calculate JA3 TLS client fingerprint (default: enabled, use --ja3=false to disable)
    #[arg(long = "ja3", default_value_t = true, action = ArgAction::Set)]
    pub ja3: bool,

    /// Include full ClientHello in JSON output
    #[arg(long = "client-hello", alias = "ch")]
    pub client_hello: bool,

    /// Path to custom JA3 signature database (JSON format)
    #[arg(long = "ja3-db", value_name = "FILE")]
    pub ja3_database: Option<PathBuf>,

    // ============ JA3S TLS Server Fingerprinting ============
    /// Calculate JA3S TLS server fingerprint (default: enabled, use --ja3s=false to disable)
    #[arg(long = "ja3s", default_value_t = true, action = ArgAction::Set)]
    pub ja3s: bool,

    /// Include full ServerHello in JSON output
    #[arg(long = "server-hello", alias = "sh")]
    pub server_hello: bool,

    /// Path to custom JA3S signature database (JSON format)
    #[arg(long = "ja3s-db", value_name = "FILE")]
    pub ja3s_database: Option<PathBuf>,

    // ============ Certificate Validation Filters ============
    /// Filter: Show only expired certificates
    #[arg(long = "expired", short = 'x')]
    pub filter_expired: bool,

    /// Filter: Show only self-signed certificates
    #[arg(long = "self-signed", short = 's')]
    pub filter_self_signed: bool,

    /// Filter: Show only hostname mismatched certificates
    #[arg(long = "mismatched", short = 'm')]
    pub filter_mismatched: bool,

    /// Filter: Show only revoked certificates
    #[arg(long = "revoked", short = 'r')]
    pub filter_revoked: bool,

    /// Filter: Show only untrusted certificates
    #[arg(long = "untrusted", short = 'u')]
    pub filter_untrusted: bool,

    // ============ JARM TLS Server Fingerprinting ============
    /// Calculate JARM TLS server fingerprint (default: enabled, use --jarm=false to disable)
    #[arg(long = "jarm", default_value_t = true, action = ArgAction::Set)]
    pub jarm: bool,

    /// Path to custom JARM signature database (JSON format)
    #[arg(long = "jarm-db", value_name = "FILE")]
    pub jarm_database: Option<PathBuf>,
}

impl Args {
    /// Validate CLI arguments for mutual exclusivity and logical consistency
    ///
    /// Returns an error if conflicting flags are used together
    pub fn validate(&self) -> anyhow::Result<()> {
        // Check for conflicting IP scanning flags
        if self.test_all_ips && self.first_ip_only {
            anyhow::bail!(
                "Cannot use --test-all-ips and --first-ip-only together. Choose one scanning mode."
            );
        }

        if self.ip.is_some() && self.test_all_ips {
            anyhow::bail!(
                "Cannot use --ip with --test-all-ips. The --ip flag specifies a single IP to scan."
            );
        }

        if self.ip.is_some() && self.first_ip_only {
            anyhow::bail!(
                "Cannot use --ip with --first-ip-only. The --ip flag already specifies a single IP to scan."
            );
        }

        Ok(())
    }

    /// Detect which STARTTLS protocol is requested
    pub fn starttls_protocol(&self) -> Option<crate::starttls::StarttlsProtocol> {
        use crate::starttls::StarttlsProtocol;

        if self.starttls_smtp {
            Some(StarttlsProtocol::SMTP)
        } else if self.starttls_imap {
            Some(StarttlsProtocol::IMAP)
        } else if self.starttls_pop3 {
            Some(StarttlsProtocol::POP3)
        } else if self.starttls_ftp {
            Some(StarttlsProtocol::FTP)
        } else if self.starttls_ldap {
            Some(StarttlsProtocol::LDAP)
        } else if self.starttls_xmpp || self.xmpp_server {
            Some(StarttlsProtocol::XMPP)
        } else if self.starttls_psql {
            Some(StarttlsProtocol::POSTGRES)
        } else if self.starttls_mysql {
            Some(StarttlsProtocol::MYSQL)
        } else if self.starttls_irc {
            Some(StarttlsProtocol::IRC)
        } else {
            None
        }
    }

    /// Check if we should run the default test suite
    pub fn run_default_suite(&self) -> bool {
        !self.protocols
            && !self.each_cipher
            && !self.cipher_per_proto
            && !self.categories
            && !self.forward_secrecy
            && !self.server_defaults
            && !self.server_preference
            && !self.headers
            && !self.vulnerabilities
            && !self.heartbleed
            && !self.client_simulation
            && !self.full
    }

    /// Check if vulnerability testing is enabled
    pub fn test_vulnerabilities(&self) -> bool {
        self.vulnerabilities
            || self.heartbleed
            || self.ccs
            || self.ticketbleed
            || self.robot
            || self.renegotiation
            || self.crime
            || self.breach
            || self.poodle
            || self.fallback
            || self.sweet32
            || self.beast
            || self.lucky13
            || self.freak
            || self.logjam
            || self.drown
            || self.early_data
            || self.full
    }

    /// Get the SNI hostname to use (custom or default)
    pub fn effective_sni(&self, default_hostname: &str) -> String {
        self.sni_name
            .clone()
            .unwrap_or_else(|| default_hostname.to_string())
    }

    /// Get list of protocols to test based on flags
    pub fn protocols_to_test(&self) -> Option<Vec<crate::protocols::Protocol>> {
        use crate::protocols::Protocol;

        // If specific protocol flags are set, only test those
        if self.ssl2 || self.ssl3 || self.tls10 || self.tls11 || self.tls12 || self.tls13 {
            let mut protocols = Vec::new();
            if self.ssl2 {
                protocols.push(Protocol::SSLv2);
            }
            if self.ssl3 {
                protocols.push(Protocol::SSLv3);
            }
            if self.tls10 {
                protocols.push(Protocol::TLS10);
            }
            if self.tls11 {
                protocols.push(Protocol::TLS11);
            }
            if self.tls12 {
                protocols.push(Protocol::TLS12);
            }
            if self.tls13 {
                protocols.push(Protocol::TLS13);
            }
            return Some(protocols);
        }

        // If --tlsall is set, skip SSL protocols
        if self.tlsall {
            return Some(vec![
                Protocol::TLS10,
                Protocol::TLS11,
                Protocol::TLS12,
                Protocol::TLS13,
            ]);
        }

        // Otherwise test all protocols
        None
    }

    /// Build a RetryConfig from CLI arguments
    ///
    /// Returns None if retry is disabled (--no-retry or --max-retries 0)
    /// Otherwise returns a configured RetryConfig with the specified parameters
    pub fn retry_config(&self) -> Option<crate::utils::retry::RetryConfig> {
        if self.no_retry || self.max_retries == 0 {
            return None;
        }

        Some(crate::utils::retry::RetryConfig::new(
            self.max_retries,
            std::time::Duration::from_millis(self.retry_backoff_ms),
            std::time::Duration::from_millis(self.max_backoff_ms),
        ))
    }

    /// Check if any certificate validation filters are active
    ///
    /// Returns true if at least one certificate filter flag is set,
    /// indicating that scan results should be filtered based on certificate validation status
    pub fn has_certificate_filters(&self) -> bool {
        self.filter_expired
            || self.filter_self_signed
            || self.filter_mismatched
            || self.filter_revoked
            || self.filter_untrusted
    }
}
