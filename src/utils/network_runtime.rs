use crate::Result;
use crate::utils::proxy::ProxyConfig;
use std::future::Future;

tokio::task_local! {
    static TASK_PROXY: Option<ProxyConfig>;
}

pub async fn scope_proxy<F, T>(proxy: Option<String>, future: F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    let parsed_proxy = proxy.as_deref().map(ProxyConfig::parse).transpose()?;
    TASK_PROXY.scope(parsed_proxy, future).await
}

pub fn current_proxy() -> Option<ProxyConfig> {
    TASK_PROXY.try_with(|proxy| proxy.clone()).ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_scope_proxy_is_not_inherited_by_spawned_tasks() {
        let observed = scope_proxy(Some("proxy.example.com:8080".to_string()), async {
            let handle = tokio::spawn(async { current_proxy() });
            Ok(handle.await.expect("spawned task should complete"))
        })
        .await
        .expect("scoped proxy should evaluate");

        assert!(observed.is_none());
    }

    #[tokio::test]
    async fn test_scope_proxy_applies_when_rescoped_inside_spawned_task() {
        let observed = tokio::spawn(async {
            scope_proxy(Some("proxy.example.com:8080".to_string()), async {
                Ok(current_proxy())
            })
            .await
        })
        .await
        .expect("spawned task should complete")
        .expect("scoped proxy should evaluate");

        let proxy = observed.expect("proxy should be visible inside scoped task");
        assert_eq!(proxy.host, "proxy.example.com");
        assert_eq!(proxy.port, 8080);
    }
}
