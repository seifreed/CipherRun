// Data module - Data file parsing and management

pub mod ca_stores;
pub mod cipher_mapping;
pub mod client_data;
pub mod curves;

// Re-export commonly used types
pub use ca_stores::{CA_STORES, CACertificate, CAStore, CAStores};
pub use cipher_mapping::{CIPHER_DB, CipherDatabase};
pub use client_data::{CLIENT_DB, ClientDatabase, ClientProfile};
pub use curves::{CURVES_DB, CurvesDatabase, EllipticCurve};
