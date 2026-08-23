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
        let mut key = [0u8; 32];
        ring::rand::SystemRandom::new()
            .fill(&mut key)
            .map_err(|_| crate::TlsError::Other("Failed to generate stream ticket key".into()))?;
        Ok(Self {
            signing_key: hmac::Key::new(hmac::HMAC_SHA256, &key),
            issued: Mutex::new(HashMap::new()),
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
        let payload = serde_json::to_vec(&claims).map_err(|error| {
            ApiError::Internal(format!("Failed to encode stream ticket: {error}"))
        })?;
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
            return Err(ApiError::Internal(
                "Too many outstanding stream tickets".to_string(),
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
        tampered[0] = if tampered[0] == b'A' { b'B' } else { b'A' };
        assert!(
            manager
                .consume(std::str::from_utf8(&tampered).unwrap(), "scan-1")
                .await
                .is_err()
        );
    }
}
