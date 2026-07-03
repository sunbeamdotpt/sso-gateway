//! Gateway-signed opaque session tokens for browser sessions.
//!
//! After a successful upstream OIDC/OAuth2/SAML login the callback handlers
//! issue an `sso_session` cookie whose value is a signed JSON payload.  The
//! shared auth middleware verifies the signature locally and constructs an
//! `AuthContext` without calling Hydra, so browser users do not need an
//! OAuth2 access token for every request.
//!
//! Tokens now carry an issuer, audience (tenant id), and a session id. The
//! session id is also recorded in the database, allowing sessions to be
//! revoked before their natural expiration.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::cookie_signer::{CookieError, CookieSigner};

/// Claims carried inside a signed session token.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SessionClaims {
    /// Gateway public subject identifier (maps to the identity in id_mappings).
    pub sub: String,
    /// Tenant the subject belongs to.
    pub tenant_id: String,
    /// Authentication method reference (e.g. `oidc`, `oauth2`, `saml`).
    pub amr: String,
    /// Token issuer, set to the gateway public base URL.
    pub iss: String,
    /// Token audience, set to the tenant id.
    pub aud: String,
    /// Random session id used for server-side revocation.
    pub sid: String,
    /// Expiration timestamp in seconds since the Unix epoch.
    pub exp: i64,
}

/// Errors from session token issuance or verification.
#[derive(Debug, thiserror::Error)]
pub enum SessionTokenError {
    #[error("invalid token format")]
    InvalidFormat,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("token expired")]
    Expired,

    #[error("invalid issuer")]
    InvalidIssuer,

    #[error("invalid audience")]
    InvalidAudience,

    #[error("session revoked")]
    Revoked,

    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl From<CookieError> for SessionTokenError {
    fn from(err: CookieError) -> Self {
        match err {
            CookieError::InvalidFormat | CookieError::WeakKey => SessionTokenError::InvalidFormat,
            CookieError::InvalidBase64 | CookieError::InvalidSignature => {
                SessionTokenError::InvalidSignature
            }
        }
    }
}

/// Issues and verifies gateway-signed opaque session tokens.
#[derive(Clone)]
pub struct SessionTokenSigner {
    signer: CookieSigner,
    ttl_seconds: i64,
    issuer: String,
}

impl SessionTokenSigner {
    /// Create a signer with the given HMAC secret, token lifetime, and issuer.
    ///
    /// # Panics
    ///
    /// Panics if `secret` is shorter than 32 bytes. The caller is expected to
    /// validate this at config load time.
    pub fn new(secret: impl AsRef<[u8]>, ttl_seconds: i64, issuer: impl Into<String>) -> Self {
        Self {
            signer: CookieSigner::new(secret).expect("session token secret must be at least 32 bytes"),
            ttl_seconds,
            issuer: issuer.into(),
        }
    }

    /// Issue a signed token for the given subject, returning both the token and
    /// its claims so the caller can persist the session id server-side.
    pub fn issue(
        &self,
        sub: &str,
        tenant_id: &str,
        amr: &str,
    ) -> Result<(String, SessionClaims), SessionTokenError> {
        let sid = Self::generate_sid();
        let claims = SessionClaims {
            sub: sub.into(),
            tenant_id: tenant_id.into(),
            amr: amr.into(),
            iss: self.issuer.clone(),
            aud: tenant_id.into(),
            sid,
            exp: (OffsetDateTime::now_utc().unix_timestamp() + self.ttl_seconds),
        };
        let payload = serde_json::to_string(&claims)?;
        let token = self.signer.sign(&payload);
        Ok((token, claims))
    }

    /// Verify a signed token and return its claims.
    ///
    /// The caller is responsible for checking revocation via `SessionStore`.
    pub fn verify(&self, token: &str) -> Result<SessionClaims, SessionTokenError> {
        let payload = self.signer.verify(token)?;
        let claims: SessionClaims = serde_json::from_str(&payload)?;
        if claims.exp < OffsetDateTime::now_utc().unix_timestamp() {
            return Err(SessionTokenError::Expired);
        }
        if claims.iss != self.issuer {
            return Err(SessionTokenError::InvalidIssuer);
        }
        if claims.aud != claims.tenant_id {
            return Err(SessionTokenError::InvalidAudience);
        }
        Ok(claims)
    }

    fn generate_sid() -> String {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_signer() -> SessionTokenSigner {
        SessionTokenSigner::new(
            "super-secret-key-that-is-at-least-32-bytes-long",
            3600,
            "https://gateway.example.com",
        )
    }

    #[test]
    fn issue_and_verify_round_trip() {
        let signer = test_signer();
        let (token, issued_claims) = signer.issue("sub-1", "tenant-1", "oidc").unwrap();
        let claims = signer.verify(&token).unwrap();
        assert_eq!(claims.sub, "sub-1");
        assert_eq!(claims.tenant_id, "tenant-1");
        assert_eq!(claims.amr, "oidc");
        assert_eq!(claims.iss, "https://gateway.example.com");
        assert_eq!(claims.aud, "tenant-1");
        assert_eq!(claims.sid, issued_claims.sid);
        assert!(!claims.sid.is_empty());
        assert!(claims.exp > OffsetDateTime::now_utc().unix_timestamp());
    }

    #[test]
    fn verify_rejects_wrong_issuer() {
        let signer = test_signer();
        let (token, _) = signer.issue("sub-1", "tenant-1", "oidc").unwrap();
        let signer2 = SessionTokenSigner::new(
            "super-secret-key-that-is-at-least-32-bytes-long",
            3600,
            "https://evil.example.com",
        );
        let err = signer2.verify(&token).unwrap_err();
        assert!(matches!(err, SessionTokenError::InvalidIssuer));
    }

    #[test]
    fn verify_rejects_tampered_token() {
        let signer = test_signer();
        let (token, _) = signer.issue("sub-1", "tenant-1", "oidc").unwrap();
        let mut chars: Vec<char> = token.chars().collect();
        if chars[10] == 'A' {
            chars[10] = 'B';
        } else {
            chars[10] = 'A';
        }
        let tampered = chars.into_iter().collect::<String>();
        assert!(matches!(
            signer.verify(&tampered).unwrap_err(),
            SessionTokenError::InvalidSignature
        ));
    }

    #[test]
    fn verify_rejects_expired_token() {
        let signer = SessionTokenSigner::new(
            "super-secret-key-that-is-at-least-32-bytes-long",
            -1,
            "https://gateway.example.com",
        );
        let (token, _) = signer.issue("sub-1", "tenant-1", "oidc").unwrap();
        assert!(matches!(
            signer.verify(&token).unwrap_err(),
            SessionTokenError::Expired
        ));
    }
}
