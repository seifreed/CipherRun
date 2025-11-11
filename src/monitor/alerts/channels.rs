// Alert Channel Trait

use crate::Result;
use crate::monitor::alerts::Alert;
use async_trait::async_trait;

/// Alert channel trait - implement this for custom alert channels
#[async_trait]
pub trait AlertChannel: Send + Sync {
    /// Send an alert through this channel
    async fn send_alert(&self, alert: &Alert) -> Result<()>;

    /// Get the channel name for logging
    fn channel_name(&self) -> &str;

    /// Test the channel connectivity (optional)
    async fn test_connection(&self) -> Result<()> {
        Ok(())
    }
}
