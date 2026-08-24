use clap::Subcommand;
use std::path::PathBuf;

#[derive(Subcommand, Debug, Clone)]
pub enum CipherRunSubcommand {
    /// Compare two versioned CipherRun scan-result JSON files
    Diff {
        /// Previous scan result JSON
        previous: PathBuf,

        /// Current scan result JSON
        current: PathBuf,

        /// Print the diff as JSON
        #[arg(long)]
        json: bool,
    },

    /// Export the versioned JSON schema for scan results
    Schema {
        /// Write the schema to a file instead of stdout
        #[arg(short, long, value_name = "PATH")]
        output: Option<PathBuf>,
    },

    /// Generate hardened TLS configuration from a versioned scan result
    Remediate {
        /// Scan result JSON produced by CipherRun
        input: PathBuf,

        /// Target configuration format
        #[arg(long, value_name = "FORMAT", value_parser = ["nginx", "apache", "haproxy", "envoy", "caddy"])]
        format: String,

        /// Write the generated configuration to a file
        #[arg(short, long, value_name = "PATH")]
        output: Option<PathBuf>,

        /// Allow replacing an existing output file
        #[arg(long)]
        overwrite: bool,
    },

    /// Scan SSH/VPN config files and source code for quantum-vulnerable algorithms
    Pqc {
        /// Path to sshd_config or SSH config file to audit
        #[arg(long, value_name = "PATH")]
        ssh: Option<PathBuf>,

        /// Path to VPN config file (WireGuard or OpenVPN) to audit
        #[arg(long, value_name = "PATH")]
        vpn: Option<PathBuf>,

        /// Root directory to scan source code for quantum-vulnerable algorithm usage
        #[arg(long, value_name = "PATH")]
        code: Option<PathBuf>,
    },
}
