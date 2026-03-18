// API Routes Module

pub mod certificates;
pub mod compliance;
pub mod health;
pub mod history;
pub mod policies;
mod policy_storage;
pub mod scans;
pub mod stats;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_routes_module_symbols() {
        let _health = health::health_check;
        let _stats = stats::get_stats;
        let _scans = scans::create_scan;
    }
}
