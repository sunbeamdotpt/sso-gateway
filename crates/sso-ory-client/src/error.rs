use thiserror::Error;

#[derive(Debug, Error)]
pub enum OryClientError {
    #[error("http request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("url construction failed: {0}")]
    Url(#[from] url::ParseError),

    #[error("ory returned error: {status} {message}")]
    Ory { status: u16, message: String },

    /// Hydra's authorization endpoint responded with an HTTP redirect.
    /// The gateway should proxy this location, and any `Set-Cookie` headers
    /// Hydra emitted (notably the `oauth2_authentication_csrf` cookie required
    /// to complete the subsequent authorize request), to the browser.
    #[error("ory returned redirect: {location}")]
    Redirect {
        location: String,
        set_cookies: Vec<String>,
    },

    #[error("missing tenant context")]
    MissingTenant,

    #[error("invalid response from ory: {0}")]
    InvalidResponse(String),
}
