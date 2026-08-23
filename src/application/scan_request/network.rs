#[derive(Debug, Clone)]
pub struct ScanRequestNetwork {
    pub ipv4_only: bool,
    pub ipv6_only: bool,
    pub proxy: Option<String>,
    pub resolvers: Vec<String>,
    pub allow_private: bool,
    pub allow_cidrs: Vec<ipnetwork::IpNetwork>,
    pub test_all_ips: bool,
    pub first_ip_only: bool,
    pub max_concurrent_ciphers: usize,
}

impl Default for ScanRequestNetwork {
    fn default() -> Self {
        Self {
            ipv4_only: false,
            ipv6_only: false,
            proxy: None,
            resolvers: Vec::new(),
            allow_private: false,
            allow_cidrs: Vec::new(),
            test_all_ips: false,
            first_ip_only: false,
            max_concurrent_ciphers: 10,
        }
    }
}

impl ScanRequestNetwork {
    pub fn permits_private_resolution(&self) -> bool {
        self.allow_private || !self.allow_cidrs.is_empty()
    }

    pub fn validate_resolved_ips(&self, ips: &[std::net::IpAddr]) -> crate::Result<()> {
        for ip in ips {
            if crate::security::is_private_ip(ip)
                && !self.allow_private
                && !self.allow_cidrs.iter().any(|cidr| cidr.contains(*ip))
            {
                return Err(crate::TlsError::InvalidInput {
                    message: format!(
                        "Resolved target uses private/reserved address {ip}; use --allow-private or an explicit --allow-cidr"
                    ),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_network_exceptions_are_explicit_and_scoped() {
        let private = "10.20.1.5".parse().unwrap();
        let outside = "10.21.1.5".parse().unwrap();
        assert!(
            ScanRequestNetwork::default()
                .validate_resolved_ips(&[private])
                .is_err()
        );

        let unrestricted = ScanRequestNetwork {
            allow_private: true,
            ..Default::default()
        };
        assert!(unrestricted.validate_resolved_ips(&[private]).is_ok());

        let scoped = ScanRequestNetwork {
            allow_cidrs: vec!["10.20.0.0/16".parse().unwrap()],
            ..Default::default()
        };
        assert!(scoped.validate_resolved_ips(&[private]).is_ok());
        assert!(scoped.validate_resolved_ips(&[outside]).is_err());
    }
}
