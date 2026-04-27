use serde::{Deserialize, Serialize};

/// Session resumption test results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionResumptionResult {
    pub session_id_reuse: SessionIdTest,
    pub session_ticket: SessionTicketTest,
    pub resumption_support: ResumptionSupport,
    #[serde(default)]
    pub inconclusive: bool,
    pub performance_gain: Option<f64>,
    pub details: String,
}

/// Session ID reuse test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionIdTest {
    pub supported: bool,
    pub session_id_length: Option<usize>,
    pub reuse_successful: bool,
    pub connections_tested: usize,
    pub reuse_count: usize,
    #[serde(default)]
    pub inconclusive: bool,
}

/// Session ticket (RFC 5077) test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTicketTest {
    pub supported: bool,
    pub ticket_lifetime: Option<u32>,
    pub ticket_size: Option<usize>,
    pub reuse_successful: bool,
    pub new_ticket_on_resume: bool,
    #[serde(default)]
    pub inconclusive: bool,
}

/// Resumption support level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResumptionSupport {
    Full,
    SessionIdOnly,
    TicketOnly,
    None,
    Unknown,
}

impl ResumptionSupport {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResumptionSupport::Full => "Full (Session ID + Tickets)",
            ResumptionSupport::SessionIdOnly => "Session ID Only",
            ResumptionSupport::TicketOnly => "Session Tickets Only",
            ResumptionSupport::None => "None",
            ResumptionSupport::Unknown => "Unknown (test inconclusive)",
        }
    }
}
