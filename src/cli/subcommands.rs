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
