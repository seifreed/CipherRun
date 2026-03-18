use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientCA {
    pub distinguished_name: String,
    pub organization: Option<String>,
    pub common_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientCAsResult {
    pub cas: Vec<ClientCA>,
    pub requires_client_auth: bool,
}
