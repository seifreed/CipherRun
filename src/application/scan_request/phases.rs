use super::ScanRequest;

impl ScanRequest {
    pub fn baseline_scan_requested(&self) -> bool {
        self.scan.full || (self.scan.all && !self.has_specific_scan_focus())
    }

    pub fn should_run_protocol_phase(&self) -> bool {
        self.scan.protocols || self.baseline_scan_requested()
    }

    pub fn should_run_cipher_phase(&self) -> bool {
        !self.scan.no_ciphersuites
            && (self.scan.each_cipher
                || self.scan.cipher_per_proto
                || self.scan.categories
                || self.scan.forward_secrecy
                || self.scan.server_defaults
                || self.scan.server_preference
                || self.baseline_scan_requested())
    }

    pub fn should_run_certificate_phase(&self) -> bool {
        self.baseline_scan_requested() || self.scan.ocsp
    }

    pub fn should_run_http_headers_phase(&self) -> bool {
        self.scan.headers || self.baseline_scan_requested()
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
        self.scan.full || self.scan.vulnerabilities || self.has_specific_vulnerability_focus()
    }

    pub fn should_calculate_rating(&self) -> bool {
        !self.scan.disable_rating && self.baseline_scan_requested()
    }

    pub fn should_enumerate_all_ciphers(&self) -> bool {
        self.scan.each_cipher
            || self.scan.cipher_per_proto
            || self.scan.categories
            || self.scan.forward_secrecy
            || self.scan.server_defaults
            || self.scan.server_preference
            || self.scan.full
    }

    pub fn should_collect_preflight_data(&self) -> bool {
        self.scan.probe_status || self.scan.pre_handshake || self.scan.ocsp
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
        self.should_run_fingerprint_flag(self.fingerprint.ja3, self.fingerprint.explicit_ja3)
    }

    pub fn should_run_ja3s_fingerprint(&self) -> bool {
        self.should_run_fingerprint_flag(self.fingerprint.ja3s, self.fingerprint.explicit_ja3s)
    }

    pub fn should_run_jarm_fingerprint(&self) -> bool {
        self.should_run_fingerprint_flag(self.fingerprint.jarm, self.fingerprint.explicit_jarm)
    }

    pub fn should_run_fingerprint_phase(&self) -> bool {
        self.should_run_ja3_fingerprint()
            || self.should_run_ja3s_fingerprint()
            || self.should_run_jarm_fingerprint()
    }
}
