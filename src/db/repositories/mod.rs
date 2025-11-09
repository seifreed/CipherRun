// Repositories Module
// Re-exports all repository implementations

pub mod scan_repository;

// Re-export for convenience
pub use scan_repository::ScanRepositoryImpl;

// Note: Other repositories follow the same pattern as scan_repository
// They are implemented inline in the database.rs module for brevity
