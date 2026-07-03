//! JWKS fetching and decoding-key resolution for OIDC ID token signature
//! verification.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::services::handlers::callback::CallbackError;

const JWKS_CACHE_TTL: Duration = Duration::from_secs(15 * 60);

type JwksCache = HashMap<String, (Vec<jsonwebtoken::jwk::Jwk>, Instant)>;

/// Resolves a [`jsonwebtoken::DecodingKey`] for a given ID token.
#[async_trait]
pub trait JwksService: Send + Sync + 'static {
    /// Fetch (or reuse a cached) JWKS from `jwks_url` and return the decoding
    /// key matching the token header.
    async fn decoding_key_for_token(
        &self,
        id_token: &str,
        jwks_url: &str,
    ) -> Result<jsonwebtoken::DecodingKey, CallbackError>;
}

/// reqwest-based JWKS service with a simple in-memory cache keyed by URL.
#[derive(Clone)]
pub struct ReqwestJwksService {
    client: reqwest::Client,
    cache: Arc<Mutex<JwksCache>>,
}

impl ReqwestJwksService {
    /// Create a new service using the provided HTTP client.
    pub fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl JwksService for ReqwestJwksService {
    async fn decoding_key_for_token(
        &self,
        id_token: &str,
        jwks_url: &str,
    ) -> Result<jsonwebtoken::DecodingKey, CallbackError> {
        let header = jsonwebtoken::decode_header(id_token).map_err(|e| {
            tracing::debug!("failed to decode ID token header: {e}");
            CallbackError::InvalidIdToken
        })?;

        let jwks = self.fetch_jwks(jwks_url).await?;

        let jwk = match &header.kid {
            Some(kid) => jwks
                .keys
                .iter()
                .find(|k| k.common.key_id.as_deref() == Some(kid)),
            None => {
                if jwks.keys.len() == 1 {
                    jwks.keys.first()
                } else {
                    None
                }
            }
        }
        .ok_or(CallbackError::InvalidIdToken)?;

        jsonwebtoken::DecodingKey::from_jwk(jwk).map_err(|e| {
            tracing::debug!("failed to build decoding key from JWK: {e}");
            CallbackError::InvalidIdToken
        })
    }
}

impl ReqwestJwksService {
    async fn fetch_jwks(&self, jwks_url: &str) -> Result<jsonwebtoken::jwk::JwkSet, CallbackError> {
        let now = Instant::now();

        {
            let cache = self.cache.lock().await;
            if let Some((jwks, fetched_at)) = cache.get(jwks_url)
                && now.duration_since(*fetched_at) < JWKS_CACHE_TTL
            {
                return Ok(jsonwebtoken::jwk::JwkSet { keys: jwks.clone() });
            }
        }

        let response = self.client.get(jwks_url).send().await.map_err(|e| {
            tracing::debug!("JWKS request failed: {e}");
            CallbackError::InvalidIdToken
        })?;

        if !response.status().is_success() {
            tracing::debug!("JWKS endpoint returned status {}", response.status());
            return Err(CallbackError::InvalidIdToken);
        }

        let jwks: jsonwebtoken::jwk::JwkSet = response.json().await.map_err(|e| {
            tracing::debug!("failed to parse JWKS response: {e}");
            CallbackError::InvalidIdToken
        })?;

        let mut cache = self.cache.lock().await;
        cache.insert(jwks_url.to_string(), (jwks.keys.clone(), now));

        Ok(jwks)
    }
}
