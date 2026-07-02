//! Upstream OAuth2 / OIDC token exchange and userinfo retrieval.

use async_trait::async_trait;
use serde_json::Value;
use sunbeam_g2v::error::ServiceError;
use tracing::{debug, instrument};

/// Token response from an upstream OAuth2 / OIDC token endpoint.
#[derive(Debug, Clone)]
pub struct UpstreamTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub id_token: Option<String>,
    pub raw: Value,
}

/// Errors from upstream OAuth2 / OIDC operations.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamOAuthError {
    #[error("missing configuration: {0}")]
    MissingConfig(String),

    #[error("upstream token error: {0}")]
    TokenExchange(String),

    #[error("upstream userinfo error: {0}")]
    Userinfo(String),

    #[error("invalid upstream URL: {0}")]
    InvalidUrl(String),

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl From<UpstreamOAuthError> for ServiceError {
    fn from(err: UpstreamOAuthError) -> Self {
        match err {
            UpstreamOAuthError::MissingConfig(msg) | UpstreamOAuthError::InvalidUrl(msg) => {
                Self::InvalidArgument(msg)
            }
            UpstreamOAuthError::TokenExchange(msg) | UpstreamOAuthError::Userinfo(msg) => {
                Self::Unavailable(msg)
            }
            UpstreamOAuthError::Http(e) => Self::Unavailable(e.to_string()),
            UpstreamOAuthError::Serialization(e) => Self::Serialization(e.to_string()),
        }
    }
}

/// Validate an upstream OAuth2 / OIDC URL.
///
/// Requires `https://`, blocks loopback/link-local/private IP literals, and
/// blocks common metadata endpoints.
pub fn validate_upstream_url(url_str: &str) -> Result<(), ServiceError> {
    let url = reqwest::Url::parse(url_str).map_err(|e| {
        ServiceError::InvalidArgument(format!("invalid upstream URL '{url_str}': {e}"))
    })?;

    if url.scheme() != "https" {
        return Err(ServiceError::InvalidArgument(
            "upstream URL must use HTTPS".into(),
        ));
    }

    let host = url
        .host_str()
        .ok_or_else(|| ServiceError::InvalidArgument("upstream URL is missing a host".into()))?;

    // Block common non-routable / metadata hostnames.
    let lower = host.to_ascii_lowercase();
    if lower == "localhost"
        || lower == "metadata"
        || lower == "metadata.google.internal"
        || lower.ends_with(".metadata")
    {
        return Err(ServiceError::InvalidArgument(
            "upstream URL resolves to a forbidden hostname".into(),
        ));
    }

    // If the host is an IP literal, block loopback, link-local and private ranges.
    // `host_str()` keeps brackets around IPv6 literals, so strip them before parsing.
    let ip_host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = ip_host.parse::<std::net::IpAddr>() && is_forbidden_ip(ip) {
        return Err(ServiceError::InvalidArgument(
            "upstream URL resolves to a forbidden IP address".into(),
        ));
    }

    Ok(())
}

fn is_forbidden_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local() || v4.is_private(),
        std::net::IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xffc0 == 0xfe80),
    }
}

/// Exchange authorization codes and fetch userinfo from upstream providers.
#[async_trait]
pub trait UpstreamOAuthClient: Send + Sync + 'static {
    async fn exchange_code(
        &self,
        config: &Value,
        code: &str,
        redirect_uri: &str,
        code_verifier: Option<&str>,
    ) -> Result<UpstreamTokenResponse, UpstreamOAuthError>;

    async fn fetch_userinfo(
        &self,
        config: &Value,
        token_response: &UpstreamTokenResponse,
    ) -> Result<Value, UpstreamOAuthError>;
}

/// reqwest-based upstream OAuth2 / OIDC client.
#[derive(Clone, Default)]
pub struct ReqwestUpstreamOAuthClient {
    client: reqwest::Client,
}

impl ReqwestUpstreamOAuthClient {
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl UpstreamOAuthClient for ReqwestUpstreamOAuthClient {
    #[instrument(skip(self, config, code_verifier))]
    async fn exchange_code(
        &self,
        config: &Value,
        code: &str,
        redirect_uri: &str,
        code_verifier: Option<&str>,
    ) -> Result<UpstreamTokenResponse, UpstreamOAuthError> {
        let token_url = config["token_url"]
            .as_str()
            .ok_or_else(|| UpstreamOAuthError::MissingConfig("missing token_url".into()))?;
        let client_id = config["client_id"]
            .as_str()
            .ok_or_else(|| UpstreamOAuthError::MissingConfig("missing client_id".into()))?;
        let client_secret = config["client_secret"]
            .as_str()
            .ok_or_else(|| UpstreamOAuthError::MissingConfig("missing client_secret".into()))?;

        if let Err(e) = validate_upstream_url(token_url) {
            return Err(UpstreamOAuthError::InvalidUrl(e.to_string()));
        }

        debug!(%token_url, "exchanging authorization code");

        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ];
        if let Some(verifier) = code_verifier {
            form.push(("code_verifier", verifier));
        }

        let response = self.client.post(token_url).form(&form).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(UpstreamOAuthError::TokenExchange(format!(
                "upstream returned {status}: {body}"
            )));
        }

        let raw: Value = response.json().await?;
        let access_token = raw["access_token"]
            .as_str()
            .ok_or_else(|| UpstreamOAuthError::TokenExchange("missing access_token".into()))?
            .to_string();
        let token_type = raw["token_type"].as_str().unwrap_or("Bearer").to_string();
        let id_token = raw["id_token"].as_str().map(String::from);

        Ok(UpstreamTokenResponse {
            access_token,
            token_type,
            id_token,
            raw,
        })
    }

    #[instrument(skip(self, config, token_response))]
    async fn fetch_userinfo(
        &self,
        config: &Value,
        token_response: &UpstreamTokenResponse,
    ) -> Result<Value, UpstreamOAuthError> {
        // OIDC providers expose userinfo_url; generic OAuth2 providers may
        // expose userinfo_url plus a JSON path to the email address.
        let userinfo_url = config["userinfo_url"]
            .as_str()
            .ok_or_else(|| UpstreamOAuthError::MissingConfig("missing userinfo_url".into()))?;

        if let Err(e) = validate_upstream_url(userinfo_url) {
            return Err(UpstreamOAuthError::InvalidUrl(e.to_string()));
        }

        debug!(%userinfo_url, "fetching upstream userinfo");

        let response = self
            .client
            .get(userinfo_url)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", token_response.access_token),
            )
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(UpstreamOAuthError::Userinfo(format!(
                "upstream returned {status}: {body}"
            )));
        }

        let mut userinfo: Value = response.json().await?;

        // For generic OAuth2 providers, normalize the configured email path
        // into a standard `email` field.
        if let Some(email_path) = config["userinfo_email_path"].as_str() {
            let email = email_path
                .split('.')
                .try_fold(&userinfo, |value, key| value.get(key));
            if let Some(email) = email.and_then(|v| v.as_str()) {
                userinfo["email"] = Value::String(email.to_string());
            }
        }

        Ok(userinfo)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use serde_json::json;

    use super::*;

    #[derive(Default)]
    struct StubUpstreamOAuthClient {
        exchange_result: Arc<Mutex<Option<Result<UpstreamTokenResponse, UpstreamOAuthError>>>>,
        userinfo_result: Arc<Mutex<Option<Result<Value, UpstreamOAuthError>>>>,
        exchange_calls: Arc<Mutex<Vec<Option<String>>>>,
    }

    #[async_trait]
    impl UpstreamOAuthClient for StubUpstreamOAuthClient {
        async fn exchange_code(
            &self,
            _config: &Value,
            _code: &str,
            _redirect_uri: &str,
            code_verifier: Option<&str>,
        ) -> Result<UpstreamTokenResponse, UpstreamOAuthError> {
            self.exchange_calls
                .lock()
                .unwrap()
                .push(code_verifier.map(String::from));
            self.exchange_result
                .lock()
                .unwrap()
                .take()
                .expect("stub not configured")
        }

        async fn fetch_userinfo(
            &self,
            _config: &Value,
            _token_response: &UpstreamTokenResponse,
        ) -> Result<Value, UpstreamOAuthError> {
            self.userinfo_result
                .lock()
                .unwrap()
                .take()
                .expect("stub not configured")
        }
    }

    #[tokio::test]
    async fn stub_client_returns_configured_results() {
        let client = StubUpstreamOAuthClient {
            exchange_result: Arc::new(Mutex::new(Some(Ok(UpstreamTokenResponse {
                access_token: "token-1".into(),
                token_type: "Bearer".into(),
                id_token: None,
                raw: json!({"access_token": "token-1"}),
            })))),
            userinfo_result: Arc::new(Mutex::new(Some(Ok(json!({"email": "a@example.com"}))))),
            ..Default::default()
        };
        let token = client
            .exchange_code(&json!({}), "code", "uri", Some("verifier"))
            .await
            .unwrap();
        assert_eq!(token.access_token, "token-1");
        {
            let calls = client.exchange_calls.lock().unwrap();
            assert_eq!(calls.as_slice(), &[Some("verifier".to_string())]);
        }
        let info = client.fetch_userinfo(&json!({}), &token).await.unwrap();
        assert_eq!(info["email"], "a@example.com");
    }

    #[test]
    fn validate_upstream_url_requires_https() {
        assert!(validate_upstream_url("http://example.com/token").is_err());
        assert!(validate_upstream_url("https://example.com/token").is_ok());
    }

    #[test]
    fn validate_upstream_url_blocks_loopback() {
        assert!(validate_upstream_url("https://127.0.0.1/token").is_err());
        assert!(validate_upstream_url("https://[::1]/token").is_err());
        assert!(validate_upstream_url("https://localhost/token").is_err());
    }

    #[test]
    fn validate_upstream_url_blocks_private_and_link_local() {
        assert!(validate_upstream_url("https://10.0.0.1/token").is_err());
        assert!(validate_upstream_url("https://192.168.1.1/token").is_err());
        assert!(validate_upstream_url("https://172.16.0.1/token").is_err());
        assert!(validate_upstream_url("https://169.254.169.254/token").is_err());
        assert!(validate_upstream_url("https://[fe80::1]/token").is_err());
    }

    #[test]
    fn validate_upstream_url_blocks_metadata_hosts() {
        assert!(validate_upstream_url("https://metadata.google.internal/token").is_err());
        assert!(validate_upstream_url("https://metadata/token").is_err());
    }

    #[test]
    fn validate_upstream_url_rejects_invalid_url() {
        assert!(validate_upstream_url("not a url").is_err());
    }

    #[test]
    fn upstream_oauth_error_converts_invalid_url() {
        let err: ServiceError = UpstreamOAuthError::InvalidUrl("bad".into()).into();
        assert!(matches!(err, ServiceError::InvalidArgument(_)));
    }
}
