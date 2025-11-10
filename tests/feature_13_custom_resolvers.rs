/// Tests for Feature 13: Custom DNS Resolvers
///
/// This test file verifies the custom DNS resolver functionality,
/// allowing users to specify custom DNS servers for resolution.

#[cfg(test)]
mod custom_resolver_tests {
    use cipherrun::utils::custom_resolvers::CustomResolver;
    use std::net::{IpAddr, SocketAddr};
    use std::str::FromStr;

    #[test]
    fn test_create_with_port() {
        let resolvers = vec!["8.8.8.8:53".to_string()];
        let resolver = CustomResolver::new(resolvers).unwrap();

        assert_eq!(resolver.count(), 1);
        let expected = SocketAddr::from_str("8.8.8.8:53").unwrap();
        assert_eq!(resolver.primary_resolver().unwrap(), expected);
    }

    #[test]
    fn test_create_without_port() {
        let resolvers = vec!["1.1.1.1".to_string()];
        let resolver = CustomResolver::new(resolvers).unwrap();

        assert_eq!(resolver.count(), 1);
        let expected = SocketAddr::new("1.1.1.1".parse().unwrap(), 53);
        assert_eq!(resolver.primary_resolver().unwrap(), expected);
    }

    #[test]
    fn test_create_multiple_resolvers() {
        let resolvers = vec![
            "8.8.8.8".to_string(),
            "1.1.1.1:53".to_string(),
            "208.67.222.222:5353".to_string(),
        ];
        let resolver = CustomResolver::new(resolvers).unwrap();

        assert_eq!(resolver.count(), 3);
    }

    #[test]
    fn test_empty_list_fails() {
        let resolvers: Vec<String> = vec![];
        let result = CustomResolver::new(resolvers);

        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_ip_fails() {
        let resolvers = vec!["invalid-ip-address".to_string()];
        let result = CustomResolver::new(resolvers);

        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_port_fails() {
        let resolvers = vec!["8.8.8.8:invalid".to_string()];
        let result = CustomResolver::new(resolvers);

        assert!(result.is_err());
    }

    #[test]
    fn test_with_timeout() {
        let resolvers = vec!["8.8.8.8".to_string()];
        let resolver = CustomResolver::new(resolvers)
            .unwrap()
            .with_timeout(std::time::Duration::from_secs(10));

        assert_eq!(resolver.delay(), std::time::Duration::from_secs(10));
    }

    #[test]
    fn test_whitespace_handling() {
        let resolvers = vec!["  8.8.8.8  ".to_string()];
        let resolver = CustomResolver::new(resolvers).unwrap();

        assert_eq!(resolver.count(), 1);
        let expected = SocketAddr::new("8.8.8.8".parse().unwrap(), 53);
        assert_eq!(resolver.primary_resolver().unwrap(), expected);
    }

    #[test]
    fn test_get_resolvers() {
        let resolvers = vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()];
        let resolver = CustomResolver::new(resolvers).unwrap();

        let all_resolvers = resolver.resolvers();
        assert_eq!(all_resolvers.len(), 2);
    }

    #[test]
    fn test_primary_resolver() {
        let resolvers = vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()];
        let resolver = CustomResolver::new(resolvers).unwrap();

        let primary = resolver.primary_resolver().unwrap();
        assert_eq!(primary.ip().to_string(), "8.8.8.8");
        assert_eq!(primary.port(), 53);
    }

    #[test]
    fn test_count() {
        let resolvers = vec![
            "8.8.8.8".to_string(),
            "1.1.1.1".to_string(),
            "208.67.222.222".to_string(),
        ];
        let resolver = CustomResolver::new(resolvers).unwrap();

        assert_eq!(resolver.count(), 3);
    }

    #[test]
    fn test_ipv6_address() {
        let resolvers = vec!["2001:4860:4860::8888".to_string()];
        let resolver = CustomResolver::new(resolvers).unwrap();

        assert_eq!(resolver.count(), 1);
        let primary = resolver.primary_resolver().unwrap();
        assert_eq!(primary.ip().to_string(), "2001:4860:4860::8888");
    }

    #[test]
    fn test_ipv6_with_port() {
        let resolvers = vec!["[2001:4860:4860::8888]:53".to_string()];
        let resolver = CustomResolver::new(resolvers).unwrap();

        assert_eq!(resolver.count(), 1);
    }

    #[test]
    fn test_cloudflare_dns() {
        let resolvers = vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()];
        let resolver = CustomResolver::new(resolvers).unwrap();

        assert_eq!(resolver.count(), 2);
        assert!(resolver.primary_resolver().is_some());
    }

    #[test]
    fn test_quad9_dns() {
        let resolvers = vec!["9.9.9.9".to_string()];
        let resolver = CustomResolver::new(resolvers).unwrap();

        assert_eq!(resolver.count(), 1);
        let primary = resolver.primary_resolver().unwrap();
        assert_eq!(primary.ip().to_string(), "9.9.9.9");
    }

    #[test]
    fn test_custom_dns_port() {
        let resolvers = vec!["dns.example.com:5353".to_string()]; // Will fail because it's not an IP
        let result = CustomResolver::new(resolvers);

        assert!(result.is_err());
    }

    #[test]
    fn test_default_timeout() {
        let resolvers = vec!["8.8.8.8".to_string()];
        let resolver = CustomResolver::new(resolvers).unwrap();

        assert_eq!(resolver.delay(), std::time::Duration::from_secs(5));
    }
}
