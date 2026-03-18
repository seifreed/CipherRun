mod insert;
mod link;
mod lookup;

use crate::application::PersistedScan;
use crate::db::CipherRunDatabase;

impl CipherRunDatabase {
    pub(crate) async fn store_certificates(
        &self,
        scan_id: i64,
        results: &PersistedScan,
    ) -> crate::Result<()> {
        for cert_info in &results.certificates {
            self.store_single_certificate(scan_id, cert_info).await?;
        }

        Ok(())
    }

    async fn store_single_certificate(
        &self,
        scan_id: i64,
        cert_info: &crate::application::persistence::PersistedCertificate,
    ) -> crate::Result<()> {
        let cert_id = self.insert_or_get_persisted_certificate(cert_info).await?;
        self.link_certificate(scan_id, cert_id, cert_info.chain_position)
            .await
    }

    async fn insert_or_get_persisted_certificate(
        &self,
        cert_info: &crate::application::persistence::PersistedCertificate,
    ) -> crate::Result<i64> {
        self.insert_or_get_certificate_direct(
            &cert_info.fingerprint_sha256,
            &cert_info.subject,
            &cert_info.issuer,
            cert_info.serial_number.as_deref(),
            cert_info.not_before,
            cert_info.not_after,
            cert_info.signature_algorithm.as_deref(),
            cert_info.public_key_algorithm.as_deref(),
            cert_info.public_key_size,
            &cert_info.san_domains,
            cert_info.is_ca,
            &cert_info.key_usage,
            &cert_info.extended_key_usage,
            cert_info.der_bytes.as_deref(),
        )
        .await
    }
}
