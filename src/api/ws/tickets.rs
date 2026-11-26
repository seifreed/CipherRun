use crate::api::middleware::AuthExtension;
use crate::api::models::error::ApiError;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{hmac, rand::SecureRandom};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::Mutex;

const TICKET_LIFETIME_SECONDS: i64 = 60;
const MAX_TICKET_BYTES: usize = 4096;
const MAX_OUTSTANDING_TICKETS: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StreamTicketClaims {
    nonce: String,
    scan_id: String,
    key_id: String,
    principal_id: String,
    tenant_id: Option<String>,
    expires_at: i64,
}

pub struct StreamTicketManager {
    signing_key: hmac::Key,
    issued: Mutex<HashMap<String, StreamTicketClaims>>,
}

impl StreamTicketManager {
    pub fn new() -> crate::Result<Self> {
        let random = ring::rand::SystemRandom::new();
        let signing_key = Self::signing_key_from_random(|key| random.fill(key))?;
        Ok(Self {
            signing_key,
            issued: Mutex::new(HashMap::new()),
        })
    }

    fn signing_key_from_random(
        fill_random: impl FnOnce(&mut [u8]) -> std::result::Result<(), ring::error::Unspecified>,
    ) -> crate::Result<hmac::Key> {
        let mut key = [0u8; 32];
        fill_random(&mut key)
            .map_err(|_| crate::TlsError::Other("Failed to generate stream ticket key".into()))?;
        Ok(hmac::Key::new(hmac::HMAC_SHA256, &key))
    }

    fn serialize_claims(claims: &impl Serialize) -> Result<Vec<u8>, ApiError> {
        serde_json::to_vec(claims).map_err(|_| {
            ApiError::internal_with_diagnostic("issue_stream_ticket", "serialization_error")
        })
    }

    pub async fn issue(
        &self,
        scan_id: &str,
        auth: &AuthExtension,
    ) -> Result<(String, chrono::DateTime<chrono::Utc>), ApiError> {
        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(TICKET_LIFETIME_SECONDS);
        let claims = StreamTicketClaims {
            nonce: uuid::Uuid::new_v4().to_string(),
            scan_id: scan_id.to_string(),
            key_id: auth.key_id.clone(),
            principal_id: auth.principal_id.clone(),
            tenant_id: auth.tenant_id.clone(),
            expires_at: expires_at.timestamp(),
        };
        let payload = Self::serialize_claims(&claims)?;
        let signature = hmac::sign(&self.signing_key, &payload);
        let token = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&payload),
            URL_SAFE_NO_PAD.encode(signature.as_ref())
        );

        let mut issued = self.issued.lock().await;
        let now = chrono::Utc::now().timestamp();
        issued.retain(|_, ticket| ticket.expires_at > now);
        if issued.len() >= MAX_OUTSTANDING_TICKETS {
            return Err(ApiError::service_unavailable_with_diagnostic(
                "issue_stream_ticket",
                "outstanding_ticket_capacity",
            ));
        }
        issued.insert(claims.nonce.clone(), claims);
        Ok((token, expires_at))
    }

    pub async fn consume(&self, token: &str, scan_id: &str) -> Result<AuthExtension, ApiError> {
        if token.len() > MAX_TICKET_BYTES {
            return Err(ApiError::Unauthorized("Invalid stream ticket".to_string()));
        }
        let (payload, signature) = token
            .split_once('.')
            .ok_or_else(|| ApiError::Unauthorized("Invalid stream ticket".to_string()))?;
        let payload = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| ApiError::Unauthorized("Invalid stream ticket".to_string()))?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| ApiError::Unauthorized("Invalid stream ticket".to_string()))?;
        hmac::verify(&self.signing_key, &payload, &signature)
            .map_err(|_| ApiError::Unauthorized("Invalid stream ticket".to_string()))?;
        let claims: StreamTicketClaims = serde_json::from_slice(&payload)
            .map_err(|_| ApiError::Unauthorized("Invalid stream ticket".to_string()))?;
        let now = chrono::Utc::now().timestamp();
        if claims.scan_id != scan_id || claims.expires_at <= now {
            return Err(ApiError::Unauthorized(
                "Expired or scan-mismatched stream ticket".to_string(),
            ));
        }

        let mut issued = self.issued.lock().await;
        issued.retain(|_, ticket| ticket.expires_at > now);
        let stored = issued
            .remove(&claims.nonce)
            .ok_or_else(|| ApiError::Unauthorized("Stream ticket already used".to_string()))?;
        if stored != claims {
            return Err(ApiError::Unauthorized("Invalid stream ticket".to_string()));
        }

        Ok(AuthExtension {
            permission: crate::api::config::Permission::ReadOnly,
            key_id: claims.key_id,
            principal_id: claims.principal_id,
            tenant_id: claims.tenant_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::config::Permission;

    fn auth() -> AuthExtension {
        AuthExtension {
            permission: Permission::User,
            key_id: "key-1".to_string(),
            principal_id: "principal-1".to_string(),
            tenant_id: Some("tenant-1".to_string()),
        }
    }

    fn claims(nonce: &str, expires_at: i64) -> StreamTicketClaims {
        StreamTicketClaims {
            nonce: nonce.to_string(),
            scan_id: "scan-1".to_string(),
            key_id: "key-1".to_string(),
            principal_id: "principal-1".to_string(),
            tenant_id: Some("tenant-1".to_string()),
            expires_at,
        }
    }

    fn signed_token(manager: &StreamTicketManager, payload: &[u8]) -> String {
        let signature = hmac::sign(&manager.signing_key, payload);
        format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(signature.as_ref())
        )
    }

    struct FailingClaims;

    impl Serialize for FailingClaims {
        fn serialize<S>(&self, _serializer: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            Err(serde::ser::Error::custom("fixture serialization failure"))
        }
    }

    #[tokio::test]
    async fn ticket_is_scan_bound_signed_and_single_use() {
        let manager = StreamTicketManager::new().expect("manager should initialize");
        let (ticket, _) = manager.issue("scan-1", &auth()).await.unwrap();

        assert!(manager.consume(&ticket, "scan-2").await.is_err());
        let consumed = manager.consume(&ticket, "scan-1").await.unwrap();
        assert_eq!(consumed.principal_id, "principal-1");
        assert!(manager.consume(&ticket, "scan-1").await.is_err());

        let (ticket, _) = manager.issue("scan-1", &auth()).await.unwrap();
        let mut tampered = ticket.into_bytes();
        tampered[0] = b'B';
        assert!(
            manager
                .consume(std::str::from_utf8(&tampered).unwrap(), "scan-1")
                .await
                .is_err()
        );
    }

    #[test]
    fn initialization_and_claim_serialization_fail_safely() {
        assert!(matches!(
            StreamTicketManager::signing_key_from_random(|_| Err(ring::error::Unspecified)),
            Err(crate::TlsError::Other(message)) if message == "Failed to generate stream ticket key"
        ));
        assert!(matches!(
            StreamTicketManager::serialize_claims(&FailingClaims),
            Err(ApiError::Internal(_))
        ));
    }

    #[tokio::test]
    async fn consume_rejects_oversized_malformed_tampered_and_invalid_claim_tickets() {
        let manager = StreamTicketManager::new().expect("manager should initialize");

        for token in [
            "x".repeat(MAX_TICKET_BYTES + 1),
            "missing-separator".to_string(),
        ] {
            assert!(matches!(
                manager.consume(&token, "scan-1").await,
                Err(ApiError::Unauthorized(_))
            ));
        }
        for token in ["!.signature", "e30.!", "e30.AAAAAAAAAAAAAAAAAAAAAA"] {
            assert!(matches!(
                manager.consume(token, "scan-1").await,
                Err(ApiError::Unauthorized(_))
            ));
        }

        let invalid_json = signed_token(&manager, b"not a claims document");
        assert!(matches!(
            manager.consume(&invalid_json, "scan-1").await,
            Err(ApiError::Unauthorized(_))
        ));

        let expired_claims = claims("expired", chrono::Utc::now().timestamp() - 1);
        let expired_payload = serde_json::to_vec(&expired_claims).unwrap();
        let expired_ticket = signed_token(&manager, &expired_payload);
        assert!(matches!(
            manager.consume(&expired_ticket, "scan-1").await,
            Err(ApiError::Unauthorized(_))
        ));
    }

    #[tokio::test]
    async fn consume_rejects_claims_that_do_not_match_the_issued_record() {
        let manager = StreamTicketManager::new().expect("manager should initialize");
        let now = chrono::Utc::now().timestamp();
        let token_claims = claims("nonce-1", now + TICKET_LIFETIME_SECONDS);
        let payload = serde_json::to_vec(&token_claims).unwrap();
        let ticket = signed_token(&manager, &payload);

        assert!(matches!(
            manager.consume(&ticket, "scan-1").await,
            Err(ApiError::Unauthorized(_))
        ));

        let mut issued_claims = token_claims.clone();
        issued_claims.principal_id = "different-principal".to_string();
        manager
            .issued
            .lock()
            .await
            .insert(token_claims.nonce.clone(), issued_claims);

        assert!(matches!(
            manager.consume(&ticket, "scan-1").await,
            Err(ApiError::Unauthorized(_))
        ));
    }

    #[tokio::test]
    async fn issue_prunes_expired_tickets_and_rejects_capacity_overflow() {
        let manager = StreamTicketManager::new().expect("manager should initialize");
        let now = chrono::Utc::now().timestamp();
        {
            let mut issued = manager.issued.lock().await;
            for index in 0..MAX_OUTSTANDING_TICKETS {
                let ticket = claims(&format!("expired-{index}"), now - 1);
                issued.insert(ticket.nonce.clone(), ticket);
            }
        }

        manager.issue("scan-1", &auth()).await.unwrap();
        {
            let mut issued = manager.issued.lock().await;
            assert_eq!(issued.len(), 1, "expired tickets should be pruned");
            issued.clear();
            for index in 0..MAX_OUTSTANDING_TICKETS {
                let ticket = claims(&format!("active-{index}"), now + 3600);
                issued.insert(ticket.nonce.clone(), ticket);
            }
        }

        let error = manager.issue("scan-1", &auth()).await.unwrap_err();
        assert!(matches!(error, ApiError::ServiceUnavailable(_)));
    }
}
