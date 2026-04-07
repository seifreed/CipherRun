// Random SNI Generator Module
// Generates random valid-looking SNI hostnames for IP address scanning

use rand::RngExt;

/// SNI Generator for creating random hostnames
pub struct SniGenerator;

impl SniGenerator {
    /// Generate random valid-looking SNI
    pub fn generate_random() -> String {
        let subdomain = Self::generate_random_label(8);
        let domain = Self::generate_random_label(10);
        let tld = Self::choose_random_tld();

        format!("{}.{}.{}", subdomain, domain, tld)
    }

    /// Generate random label (DNS-valid)
    /// Length between min_len and min_len+7 characters
    /// Must start and end with alphanumeric, can contain hyphens in middle
    fn generate_random_label(min_len: usize) -> String {
        let mut rng = rand::rng();
        let length = rng.random_range(min_len..min_len + 7);

        let mut label = String::with_capacity(length);

        // First character must be alphanumeric
        label.push(Self::random_alphanum_char());

        // Middle characters can include hyphens
        for _i in 1..length - 1 {
            if rng.random_bool(0.1) {
                // 10% chance of hyphen
                label.push('-');
            } else {
                label.push(Self::random_alphanum_char());
            }
        }

        // Last character must be alphanumeric
        if length > 1 {
            label.push(Self::random_alphanum_char());
        }

        label
    }

    /// Generate random alphanumeric character (lowercase)
    fn random_alphanum_char() -> char {
        let mut rng = rand::rng();
        const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        CHARSET[rng.random_range(0..CHARSET.len())] as char
    }

    /// Choose random realistic TLD
    fn choose_random_tld() -> &'static str {
        let mut rng = rand::rng();
        const TLDS: &[&str] = &[
            "com", "net", "org", "io", "co", "dev", "app", "cloud", "tech", "online", "site",
            "info", "biz", "me", "cc", "tv", "xyz", "live", "store", "digital",
        ];
        TLDS[rng.random_range(0..TLDS.len())]
    }

    /// Generate random SNI with custom pattern
    pub fn generate_with_pattern(pattern: &str) -> String {
        // Pattern can contain:
        // - {subdomain}: random subdomain
        // - {domain}: random domain
        // - {tld}: random TLD
        // - {random}: random 8-char string

        let mut result = pattern.to_string();

        result = result.replace("{subdomain}", &Self::generate_random_label(5));
        result = result.replace("{domain}", &Self::generate_random_label(8));
        result = result.replace("{tld}", Self::choose_random_tld());
        result = result.replace("{random}", &Self::generate_random_label(8));

        result
    }

    /// Validate if SNI is a valid hostname format
    pub fn is_valid_hostname(hostname: &str) -> bool {
        if hostname.is_empty() || hostname.len() > 253 {
            return false;
        }

        let labels: Vec<&str> = hostname.split('.').collect();

        if labels.len() < 2 {
            return false; // Must have at least domain.tld
        }

        for label in labels {
            if label.is_empty() || label.len() > 63 {
                return false;
            }

            // Must start and end with alphanumeric
            if !label
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric())
            {
                return false;
            }

            if !label
                .chars()
                .last()
                .is_some_and(|c| c.is_ascii_alphanumeric())
            {
                return false;
            }

            // Can only contain alphanumeric and hyphens
            if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return false;
            }
        }

        true
    }

    /// Generate multiple random SNIs
    pub fn generate_multiple(count: usize) -> Vec<String> {
        (0..count).map(|_| Self::generate_random()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random() {
        let sni = SniGenerator::generate_random();
        assert!(SniGenerator::is_valid_hostname(&sni));
        assert!(sni.contains('.'));
        assert!(sni.len() > 5);
    }

    #[test]
    fn test_generate_multiple() {
        let snis = SniGenerator::generate_multiple(5);
        assert_eq!(snis.len(), 5);

        // All should be valid
        for sni in snis {
            assert!(SniGenerator::is_valid_hostname(&sni));
        }
    }

    #[test]
    fn test_generate_multiple_zero_count() {
        let snis = SniGenerator::generate_multiple(0);
        assert!(snis.is_empty());
    }

    #[test]
    fn test_generate_with_pattern() {
        let sni = SniGenerator::generate_with_pattern("{subdomain}.example.com");
        assert!(sni.ends_with(".example.com"));
        assert!(SniGenerator::is_valid_hostname(&sni));
    }

    #[test]
    fn test_generate_with_pattern_replaces_placeholders() {
        let sni = SniGenerator::generate_with_pattern("{subdomain}.{domain}.{tld}-{random}");
        assert!(!sni.contains('{'));
        assert!(sni.contains('.'));
        assert!(SniGenerator::is_valid_hostname(&sni));
    }

    #[test]
    fn test_is_valid_hostname() {
        assert!(SniGenerator::is_valid_hostname("example.com"));
        assert!(SniGenerator::is_valid_hostname("sub.example.com"));
        assert!(SniGenerator::is_valid_hostname("my-site.example.org"));

        assert!(!SniGenerator::is_valid_hostname(""));
        assert!(!SniGenerator::is_valid_hostname("example"));
        assert!(!SniGenerator::is_valid_hostname("-example.com"));
        assert!(!SniGenerator::is_valid_hostname("example-.com"));
        assert!(!SniGenerator::is_valid_hostname("exam ple.com"));
    }

    #[test]
    fn test_random_label() {
        let label = SniGenerator::generate_random_label(5);
        assert!(label.len() >= 5);
        assert!(label.len() <= 12);

        // First and last chars should be alphanumeric
        let first = label.chars().next().expect("test assertion should succeed");
        let last = label.chars().last().expect("test assertion should succeed");
        assert!(first.is_ascii_alphanumeric());
        assert!(last.is_ascii_alphanumeric());
    }

    #[test]
    fn test_generate_random_unique() {
        let sni1 = SniGenerator::generate_random();
        let sni2 = SniGenerator::generate_random();

        // Should generate different SNIs (with very high probability)
        assert_ne!(sni1, sni2);
    }

    #[test]
    fn test_is_valid_hostname_rejects_long_labels_and_hosts() {
        let long_label = "a".repeat(64);
        let hostname = format!("{}.com", long_label);
        assert!(!SniGenerator::is_valid_hostname(&hostname));

        let long_host = format!("{}.com", "a".repeat(260));
        assert!(!SniGenerator::is_valid_hostname(&long_host));
    }

    #[test]
    fn test_is_valid_hostname_rejects_invalid_characters() {
        assert!(!SniGenerator::is_valid_hostname("bad_name.example"));
        assert!(!SniGenerator::is_valid_hostname("bad$name.example"));
    }

    #[test]
    fn test_generate_multiple_zero() {
        let snis = SniGenerator::generate_multiple(0);
        assert!(snis.is_empty());
    }

    #[test]
    fn test_is_valid_hostname_rejects_trailing_dot() {
        assert!(!SniGenerator::is_valid_hostname("example.com."));
    }

    #[test]
    fn test_generate_with_pattern_no_placeholders() {
        let pattern = "static.example.com";
        let sni = SniGenerator::generate_with_pattern(pattern);
        assert_eq!(sni, pattern);
        assert!(SniGenerator::is_valid_hostname(&sni));
    }

    #[test]
    fn test_is_valid_hostname_allows_numeric() {
        assert!(SniGenerator::is_valid_hostname("a1-2.example"));
    }
}
