// Output format configuration arguments
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use clap::Args;
use std::path::PathBuf;

/// Output format and display options
///
/// This struct contains all arguments related to output formatting,
/// including JSON, CSV, HTML, XML formats, verbosity, colors, and logging.
#[derive(Args, Debug, Clone, Default)]
pub struct OutputArgs {
    /// Output to JSON file
    #[arg(long = "json", value_name = "FILE", id = "output_json")]
    pub json: Option<PathBuf>,

    /// Output full multi-IP report to JSON (when multi-IP scanning is used)
    #[arg(
        long = "json-multi-ip",
        value_name = "FILE",
        id = "output_json_multi_ip"
    )]
    pub json_multi_ip: Option<PathBuf>,

    /// Pretty print JSON output
    #[arg(long = "json-pretty")]
    pub json_pretty: bool,

    /// Output to CSV file
    #[arg(long = "csv", value_name = "FILE")]
    pub csv: Option<PathBuf>,

    /// Output to HTML file
    #[arg(long = "html", value_name = "FILE")]
    pub html: Option<PathBuf>,

    /// Output to XML file
    #[arg(long = "xml", value_name = "FILE")]
    pub xml: Option<PathBuf>,

    /// Output all supported formats with basename (like nmap -oA)
    #[arg(short = 'o', long = "output-all", value_name = "BASENAME")]
    pub output_all: Option<PathBuf>,

    /// Prefix for output filenames
    #[arg(long = "outprefix", value_name = "PREFIX")]
    pub outprefix: Option<String>,

    /// Quiet mode (no banner)
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,

    /// Wide output
    #[arg(long = "wide")]
    pub wide: bool,

    /// Verbose level (0-6)
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Color output mode (0-3)
    #[arg(long = "color", value_name = "MODE", default_value = "2")]
    pub color: u8,

    /// Disable colored output (alias for --color 0)
    #[arg(long = "no-colour")]
    pub no_colour: bool,

    /// Disable colored output (US spelling, alias for --color 0)
    #[arg(long = "no-color")]
    pub no_color: bool,

    /// Colorblind mode (adjust colors for accessibility)
    #[arg(long = "colorblind")]
    pub colorblind: bool,

    /// Log file
    #[arg(long = "logfile", value_name = "FILE")]
    pub logfile: Option<PathBuf>,

    /// Append to output files instead of overwriting
    #[arg(long = "append")]
    pub append: bool,

    /// Overwrite output files without prompting
    #[arg(long = "overwrite")]
    pub overwrite: bool,

    /// Show hints for findings
    #[arg(long = "hints")]
    pub hints: bool,

    /// Use IANA/RFC cipher names instead of OpenSSL names
    #[arg(long = "iana-names")]
    pub iana_names: bool,

    /// Show RFC/IANA cipher names instead of OpenSSL names
    #[arg(long = "mapping", value_name = "no-openssl|no-rfc")]
    pub cipher_mapping: Option<String>,

    /// Show hexadecimal cipher IDs
    #[arg(long = "show-cipher-ids")]
    pub show_cipher_ids: bool,

    /// Show each cipher tested (not just supported ones)
    #[arg(long = "show-each")]
    pub show_each: bool,

    /// Show handshake times in milliseconds
    #[arg(long = "show-times")]
    pub show_times: bool,

    /// Warning control mode (batch, off, or default)
    #[arg(long = "warnings", value_name = "MODE")]
    pub warnings: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        args: OutputArgs,
    }

    #[test]
    fn test_output_args_defaults_from_clap() {
        let parsed = TestCli::parse_from(["test"]);
        let args = parsed.args;

        assert!(args.json.is_none());
        assert!(args.json_multi_ip.is_none());
        assert!(!args.json_pretty);
        assert!(args.csv.is_none());
        assert!(args.html.is_none());
        assert!(args.xml.is_none());
        assert!(args.output_all.is_none());
        assert!(args.outprefix.is_none());
        assert!(!args.quiet);
        assert!(!args.wide);
        assert_eq!(args.verbose, 0);
        assert_eq!(args.color, 2);
        assert!(!args.no_colour);
        assert!(!args.no_color);
        assert!(!args.colorblind);
        assert!(args.logfile.is_none());
        assert!(!args.append);
        assert!(!args.overwrite);
        assert!(!args.hints);
        assert!(!args.iana_names);
        assert!(args.cipher_mapping.is_none());
        assert!(!args.show_cipher_ids);
        assert!(!args.show_each);
        assert!(!args.show_times);
        assert!(args.warnings.is_none());
    }

    #[test]
    fn test_output_args_no_color_flags() {
        let parsed = TestCli::parse_from(["test", "--no-color"]);
        let args = parsed.args;

        assert!(args.no_color);
        assert!(!args.no_colour);
    }

    #[test]
    fn test_output_args_no_colour_alias() {
        let parsed = TestCli::parse_from(["test", "--no-colour"]);
        let args = parsed.args;

        assert!(args.no_colour);
        assert!(!args.no_color);
    }
}
