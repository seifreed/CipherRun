use super::ScanRequest;

impl ScanRequest {
    pub fn baseline_scan_requested(&self) -> bool {
        self.scan.scope.full || (self.scan.scope.all && !self.has_specific_scan_focus())
    }

    pub fn should_run_protocol_phase(&self) -> bool {
        // The cipher phase enumerates ciphers per *supported protocol*, so it
        // depends on the protocol phase having run. A standalone cipher-focus
        // flag (e.g. --each-cipher) must therefore also pull in the protocol
        // phase, otherwise cipher enumeration sees no protocols and reports
        // "0 protocols / 0 ciphers".
        //
        // PQC readiness also consumes the protocol list (TLS 1.3-exclusive
        // bonus + legacy-protocol downgrade check). Without it, --pq-readiness
        // alone would score a TLS 1.3-only server as lacking TLS 1.3 and emit a
        // spurious "Enable TLS 1.3" recommendation.
        self.scan.proto.enabled
            || self.protocols_to_test().is_some()
            || self.baseline_scan_requested()
            || self.should_run_cipher_phase()
            || self.scan.ciphers.pqc_readiness
    }

    pub fn should_run_cipher_phase(&self) -> bool {
        !self.scan.ciphers.no_ciphersuites
            && (self.scan.ciphers.each_cipher
                || self.scan.ciphers.cipher_per_proto
                || self.scan.ciphers.categories
                || self.scan.ciphers.forward_secrecy
                || self.scan.ciphers.server_defaults
                || self.scan.ciphers.server_preference
                || self.baseline_scan_requested())
    }

    pub fn should_run_certificate_phase(&self) -> bool {
        // PQC readiness inspects the leaf certificate signature algorithm to
        // award the PQC-certificate bonus; without the certificate phase,
        // --pq-readiness alone cannot detect a PQC/hybrid certificate and would
        // wrongly recommend migrating away from one the server already uses.
        self.baseline_scan_requested()
            || self.scan.certs.ocsp
            || self.scan.certs.analyze_certificates
            || self.scan.ciphers.pqc_readiness
    }

    pub fn should_run_http_headers_phase(&self) -> bool {
        self.scan.prefs.headers || self.http.assume_http || self.baseline_scan_requested()
    }

    pub fn should_run_client_simulation_phase(&self) -> bool {
        self.fingerprint.client_simulation || self.baseline_scan_requested()
    }

    pub fn should_run_alpn_phase(&self) -> bool {
        self.baseline_scan_requested()
    }

    pub fn should_run_intolerance_phase(&self) -> bool {
        self.baseline_scan_requested()
    }

    pub fn should_run_vulnerability_phase(&self) -> bool {
        self.scan.scope.full
            || self.scan.vulns.vulnerabilities
            || self.has_specific_vulnerability_focus()
    }

    pub fn should_calculate_rating(&self) -> bool {
        !self.scan.prefs.disable_rating && self.baseline_scan_requested()
    }

    pub fn effective_sni(&self, default_hostname: &str) -> String {
        self.tls
            .sni_name
            .clone()
            .unwrap_or_else(|| default_hostname.to_string())
    }

    pub fn should_enumerate_all_ciphers(&self) -> bool {
        self.scan.ciphers.each_cipher
            || self.scan.ciphers.cipher_per_proto
            || self.scan.ciphers.categories
            || self.scan.ciphers.forward_secrecy
            || self.scan.ciphers.server_defaults
            || self.scan.ciphers.server_preference
            || self.scan.scope.full
    }

    pub fn should_collect_preflight_data(&self) -> bool {
        self.scan.prefs.probe_status || self.scan.prefs.pre_handshake || self.scan.certs.ocsp
    }

    pub fn has_explicit_fingerprint_focus(&self) -> bool {
        (self.fingerprint.explicit_ja3 && self.fingerprint.ja3)
            || (self.fingerprint.explicit_ja3s && self.fingerprint.ja3s)
            || (self.fingerprint.explicit_jarm && self.fingerprint.jarm)
    }

    fn should_run_fingerprint_flag(&self, enabled: bool, explicit: bool) -> bool {
        if self.baseline_scan_requested() {
            enabled
        } else if self.has_explicit_fingerprint_focus() {
            explicit && enabled
        } else {
            false
        }
    }

    pub fn should_run_ja3_fingerprint(&self) -> bool {
        // --export-hello needs the captured ClientHello, so force the JA3 capture.
        self.fingerprint.export_hello.is_some()
            || self.should_run_fingerprint_flag(self.fingerprint.ja3, self.fingerprint.explicit_ja3)
    }

    pub fn should_run_ja3s_fingerprint(&self) -> bool {
        // --export-hello needs the captured ServerHello, so force the JA3S capture.
        self.fingerprint.export_hello.is_some()
            || self
                .should_run_fingerprint_flag(self.fingerprint.ja3s, self.fingerprint.explicit_ja3s)
    }

    pub fn should_run_jarm_fingerprint(&self) -> bool {
        self.should_run_fingerprint_flag(self.fingerprint.jarm, self.fingerprint.explicit_jarm)
    }

    pub fn should_run_fingerprint_phase(&self) -> bool {
        self.should_run_ja3_fingerprint()
            || self.should_run_ja3s_fingerprint()
            || self.should_run_jarm_fingerprint()
    }

    pub fn has_effective_scan_workload(&self) -> bool {
        self.should_run_protocol_phase()
            || self.should_run_cipher_phase()
            || self.should_run_certificate_phase()
            || self.should_run_http_headers_phase()
            || self.should_run_client_simulation_phase()
            || self.should_run_vulnerability_phase()
            || self.should_run_fingerprint_phase()
            || self.should_run_alpn_phase()
            || self.should_run_intolerance_phase()
            || self.scan.ciphers.show_sigs
            || (self.scan.ciphers.show_groups && !self.scan.ciphers.no_groups)
            || self.scan.ciphers.show_client_cas
            || self.should_collect_preflight_data()
    }
}

#[cfg(test)]
mod tests {
    use super::ScanRequest;

    #[test]
    fn test_pqc_readiness_pulls_in_protocol_phase() {
        let mut args = ScanRequest::default();
        args.scan.ciphers.pqc_readiness = true;
        assert!(
            args.should_run_protocol_phase(),
            "--pq-readiness must run the protocol phase it consumes"
        );
    }

    #[test]
    fn test_pqc_readiness_pulls_in_certificate_phase() {
        let mut args = ScanRequest::default();
        args.scan.ciphers.pqc_readiness = true;
        assert!(
            args.should_run_certificate_phase(),
            "--pq-readiness must run the certificate phase it consumes"
        );
    }

    #[test]
    fn test_default_request_runs_neither_protocol_nor_certificate_phase() {
        let args = ScanRequest::default();
        assert!(!args.should_run_protocol_phase());
        assert!(!args.should_run_certificate_phase());
    }
}
