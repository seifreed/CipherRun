use super::super::{
    ClientCAsResult, ScannerFormatter, print_section_header, truncate_with_ellipsis,
};
use colored::*;

impl<'a> ScannerFormatter<'a> {
    pub fn display_client_cas_results(&self, results: &ClientCAsResult) {
        print_section_header("Client Certificate CAs:");

        if !results.requires_client_auth {
            println!(
                "  {}",
                "Server does not require client authentication".yellow()
            );
            return;
        }

        println!(
            "  {} Server requires client certificate authentication",
            "Y".green()
        );
        println!("  Acceptable CAs: {}", results.cas.len());

        if results.cas.is_empty() {
            println!("\n  {}", "No CA restrictions (any CA accepted)".cyan());
            return;
        }

        println!();
        for (i, ca) in results.cas.iter().enumerate() {
            self.display_single_client_ca(i, ca);
        }
    }

    fn display_single_client_ca(&self, index: usize, ca: &crate::protocols::client_cas::ClientCA) {
        println!("  {}. Client CA:", index + 1);

        if let Some(cn) = &ca.common_name {
            println!("     CN:  {}", cn.green());
        }

        if let Some(org) = &ca.organization {
            println!("     Org: {}", org.cyan());
        }

        let dn_preview = truncate_with_ellipsis(&ca.distinguished_name, 60);
        println!("     DN:  {}", dn_preview.dimmed());
    }
}
