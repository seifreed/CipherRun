// Repositories Module
// Re-exports all repository implementations

pub mod scan_repository;

// Re-export for convenience
pub use scan_repository::ScanRepositoryImpl;

// Note: Other repositories follow the same pattern as scan_repository
// They are implemented inline in the database.rs module for brevity

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repository_reexport_type_name() {
        let name = std::any::type_name::<ScanRepositoryImpl>();
        assert!(name.contains("ScanRepositoryImpl"));
    }
}
