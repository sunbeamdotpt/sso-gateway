use thiserror::Error;

#[derive(Debug, Error)]
pub enum OpenFgaClientError {
    #[error("http request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("url construction failed: {0}")]
    Url(#[from] url::ParseError),

    #[error("openfga returned error: {status} {message}")]
    OpenFga { status: u16, message: String },

    #[error("missing store context")]
    MissingStore,

    #[error("invalid response from openfga: {0}")]
    InvalidResponse(String),
}
