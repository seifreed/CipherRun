use crate::api::routes::history::HistoryQuery;
use crate::application::ScanHistoryQuery;
use crate::utils::network::normalize_dns_hostname;

pub fn history_query_from_api(domain: String, query: &HistoryQuery) -> ScanHistoryQuery {
    ScanHistoryQuery {
        hostname: normalize_dns_hostname(domain),
        port: query.port,
        limit: query.limit,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_query_from_api_preserves_domain_and_filters() {
        let api_query = HistoryQuery {
            port: 8443,
            limit: 25,
        };

        let mapped = history_query_from_api("example.com".to_string(), &api_query);

        assert_eq!(mapped.hostname, "example.com");
        assert_eq!(mapped.port, 8443);
        assert_eq!(mapped.limit, 25);
    }

    #[test]
    fn history_query_from_api_normalizes_rooted_fqdn() {
        let api_query = HistoryQuery {
            port: 443,
            limit: 10,
        };

        let mapped = history_query_from_api("example.com.".to_string(), &api_query);

        assert_eq!(mapped.hostname, "example.com");
        assert_eq!(mapped.port, 443);
        assert_eq!(mapped.limit, 10);
    }
}
