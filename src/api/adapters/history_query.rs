use crate::api::routes::history::HistoryQuery;
use crate::application::ScanHistoryQuery;

pub fn history_query_from_api(domain: String, query: &HistoryQuery) -> ScanHistoryQuery {
    ScanHistoryQuery {
        hostname: domain,
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
}
