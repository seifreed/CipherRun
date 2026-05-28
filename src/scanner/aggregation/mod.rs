// CipherRun - Conservative Aggregation for Multi-IP Scans
// Copyright (C) 2024 Marc Rivero López
// Licensed under GPL-3.0

//! Conservative aggregation module for combining scan results from multiple IPs.
//!
//! This module implements a worst-case aggregation strategy:
//! - Protocols: Only marked as supported if ALL IPs support them
//! - Cipher suites: Union of all cipher suites across all IPs
//! - Grade: Takes the WORST (lowest) grade from all IPs
//! - Certificates: Most common certificate chain, or marks differences
//!
//! This conservative approach ensures that the aggregated result represents
//! the weakest security posture in a load-balanced environment.

mod certificate;
mod ciphers;
mod grade;
mod protocols;
mod session;

use crate::certificates::parser::{CertificateChain, CertificateInfo};
use crate::ciphers::tester::ProtocolCipherSummary;
use crate::protocols::{Protocol, ProtocolTestResult};
use crate::scanner::inconsistency::{Inconsistency, SingleIpScanResult};
use crate::scanner::results::serialize_sorted_map;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

pub(super) fn certificate_signature(cert: &CertificateInfo) -> String {
    if let Some(fingerprint) = cert.fingerprint_sha256.as_ref() {
        return format!("fp:{}", fingerprint);
    }

    if !cert.der_bytes.is_empty() {
        return format!("der:{}", hex::encode(&cert.der_bytes));
    }

    serde_json::to_string(cert).unwrap_or_else(|_| {
        format!(
            "subject={};issuer={};serial={};not_before={};not_after={}",
            cert.subject, cert.issuer, cert.serial_number, cert.not_before, cert.not_after
        )
    })
}

pub(super) fn certificate_chain_signature(chain: &CertificateChain) -> String {
    if chain.certificates.is_empty() {
        return "<empty>".to_string();
    }

    chain
        .certificates
        .iter()
        .map(certificate_signature)
        .collect::<Vec<_>>()
        .join("\u{1f}")
}

/// Aggregated scan result representing the conservative view across all IPs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedScanResult {
    /// Protocol test results (only protocols supported by ALL IPs)
    pub protocols: Vec<ProtocolTestResult>,

    /// Cipher suites (union of all ciphers across all IPs)
    #[serde(serialize_with = "serialize_sorted_map")]
    pub ciphers: HashMap<Protocol, ProtocolCipherSummary>,

    /// Overall grade (WORST grade from all IPs)
    pub grade: (String, u8),

    /// Most common certificate chain (leaf returned, or indication of differences)
    pub certificate_info: Option<CertificateInfo>,
    pub certificate_consistent: bool,

    /// List of detected inconsistencies
    pub inconsistencies: Vec<Inconsistency>,

    /// ALPN protocols (intersection - only those supported by all)
    pub alpn_protocols: Vec<String>,

    /// Session resumption (conservative - Some(true) only if all measured backends support it)
    pub session_resumption_caching: Option<bool>,
    pub session_resumption_tickets: Option<bool>,
}

/// Conservative aggregator for multi-IP scan results
pub struct ConservativeAggregator {
    pub(super) results: HashMap<IpAddr, SingleIpScanResult>,
    pub(super) inconsistencies: Vec<Inconsistency>,
}

impl ConservativeAggregator {
    /// Create a new conservative aggregator
    pub fn new(
        results: HashMap<IpAddr, SingleIpScanResult>,
        inconsistencies: Vec<Inconsistency>,
    ) -> Self {
        Self {
            results,
            inconsistencies,
        }
    }

    /// Aggregate all results using conservative strategy
    pub fn aggregate(&self) -> AggregatedScanResult {
        AggregatedScanResult {
            protocols: self.aggregate_protocols_conservative(),
            ciphers: self.aggregate_ciphers_conservative(),
            grade: self.aggregate_grade_conservative(),
            certificate_info: self.aggregate_certificate(),
            certificate_consistent: self.check_certificate_consistency(),
            inconsistencies: self.inconsistencies.clone(),
            alpn_protocols: self.aggregate_alpn_conservative(),
            session_resumption_caching: self.aggregate_session_resumption_caching(),
            session_resumption_tickets: self.aggregate_session_resumption_tickets(),
        }
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
