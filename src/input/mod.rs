// Input processing module
// Handles various input formats: ASN, CIDR, IP, hostname

pub mod asn_cidr;

pub use asn_cidr::{AsnCidrParser, CidrExpansion, ExpandedInput, InputType};

#[cfg(test)]
mod tests {
    use super::*;
    use ipnetwork::IpNetwork;
    use std::net::Ipv4Addr;

    #[test]
    fn test_cidr_expansion_total_and_iter() {
        let network = IpNetwork::new(Ipv4Addr::new(192, 0, 2, 0).into(), 30)
            .expect("test assertion should succeed");
        let expansion = CidrExpansion::Network { network, total: 4 };

        assert_eq!(expansion.total_ips(), 4);
        assert_eq!(expansion.iter().count() as u64, 4);
    }

    #[test]
    fn test_input_type_construction() {
        let input = InputType::Hostname("example.com".to_string());

        match input {
            InputType::Hostname(hostname) => assert_eq!(hostname, "example.com"),
            _ => panic!("expected hostname input type"),
        }
    }

    #[test]
    fn test_cidr_expansion_network_accessor() {
        let network: IpNetwork = "198.51.100.0/30".parse().expect("valid network");
        let expansion = CidrExpansion::Network { network, total: 4 };
        assert_eq!(expansion.network().prefix(), 30);
    }

    #[test]
    fn test_cidr_expansion_full_list_total() {
        let network: IpNetwork = "192.0.2.0/30".parse().expect("valid network");
        let ips = network.iter().collect::<Vec<_>>();
        let expansion = CidrExpansion::FullList {
            network,
            ips,
            total: 4,
        };
        assert_eq!(expansion.total_ips(), 4);
    }

    #[test]
    fn test_input_type_ip_construction() {
        let ip: std::net::IpAddr = "192.0.2.5".parse().expect("valid ip");
        let input = InputType::Ip(ip);
        match input {
            InputType::Ip(addr) => assert_eq!(addr, ip),
            _ => panic!("expected ip input type"),
        }
    }

    #[test]
    fn test_input_type_asn_and_cidr_construction() {
        let input = InputType::Asn("AS13335".to_string());
        match input {
            InputType::Asn(asn) => assert_eq!(asn, "AS13335"),
            _ => panic!("expected asn input type"),
        }

        let input = InputType::Cidr("192.0.2.0/24".to_string());
        match input {
            InputType::Cidr(cidr) => assert_eq!(cidr, "192.0.2.0/24"),
            _ => panic!("expected cidr input type"),
        }
    }
}
