use rand::RngCore;
use thiserror::Error;

const VERIFICATION_TOKEN_BYTES: usize = 32;
const TXT_RECORD_PREFIX: &str = "sunbeam-verify=";

#[derive(Debug, Error)]
pub enum DomainVerificationError {
    #[error("dns lookup failed: {0}")]
    DnsLookup(String),

    #[error("invalid domain: {0}")]
    InvalidDomain(String),
}

/// Generate a cryptographically random verification token suitable for a DNS
/// TXT record. The token is returned as a lower-case hex string.
pub fn generate_verification_token() -> String {
    let mut bytes = [0u8; VERIFICATION_TOKEN_BYTES];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Build the full expected TXT record value for a given token.
pub fn build_txt_record_value(token: &str) -> String {
    format!("{TXT_RECORD_PREFIX}{token}")
}

/// Resolve TXT records for `domain` and return whether the expected
/// `sunbeam-verify=<token>` record is present.
pub async fn verify_domain<R: DnsResolver>(
    resolver: &R,
    domain: &str,
    token: &str,
) -> Result<bool, DomainVerificationError> {
    let expected = build_txt_record_value(token);
    let records = resolver.txt_records(domain).await?;
    Ok(records.iter().any(|record| record.trim() == expected))
}

/// Abstraction over DNS resolution so tests can avoid real network calls.
pub trait DnsResolver: Send + Sync {
    fn txt_records(
        &self,
        domain: &str,
    ) -> impl std::future::Future<Output = Result<Vec<String>, DomainVerificationError>> + Send;
}

/// Real DNS resolver backed by hickory-resolver.
pub struct HickoryDnsResolver;

impl HickoryDnsResolver {
    pub fn new() -> Self {
        Self
    }
}

impl Default for HickoryDnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsResolver for HickoryDnsResolver {
    async fn txt_records(
        &self,
        domain: &str,
    ) -> Result<Vec<String>, DomainVerificationError> {
        let resolver = hickory_resolver::TokioResolver::builder_tokio()
            .map_err(|e| DomainVerificationError::DnsLookup(e.to_string()))?
            .build()
            .map_err(|e| DomainVerificationError::DnsLookup(e.to_string()))?;
        let lookup = resolver
            .txt_lookup(domain)
            .await
            .map_err(|e| DomainVerificationError::DnsLookup(e.to_string()))?;

        let records: Vec<String> = lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                hickory_resolver::proto::rr::RData::TXT(txt) => Some(txt),
                _ => None,
            })
            .flat_map(|txt| txt.txt_data.iter().map(|b| String::from_utf8_lossy(b).to_string()))
            .collect();
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    struct MockResolver {
        records: HashMap<String, Vec<String>>,
    }

    impl DnsResolver for MockResolver {
        async fn txt_records(
            &self,
            domain: &str,
        ) -> Result<Vec<String>, DomainVerificationError> {
            Ok(self.records.get(domain).cloned().unwrap_or_default())
        }
    }

    #[test]
    fn generate_verification_token_is_hex_encoded() {
        let token = generate_verification_token();
        assert_eq!(token.len(), VERIFICATION_TOKEN_BYTES * 2);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(hex::decode(&token).is_ok());
    }

    #[test]
    fn generate_verification_token_is_unique() {
        let a = generate_verification_token();
        let b = generate_verification_token();
        assert_ne!(a, b);
    }

    #[test]
    fn build_txt_record_value_includes_prefix() {
        let token = "abc123";
        assert_eq!(build_txt_record_value(token), "sunbeam-verify=abc123");
    }

    #[tokio::test]
    async fn verify_domain_matches_expected_record() {
        let token = generate_verification_token();
        let expected = build_txt_record_value(&token);
        let resolver = MockResolver {
            records: HashMap::from([("example.com".to_string(), vec![expected.clone()])]),
        };

        assert!(verify_domain(&resolver, "example.com", &token)
            .await
            .expect("verification should succeed"));
    }

    #[tokio::test]
    async fn verify_domain_rejects_missing_record() {
        let token = generate_verification_token();
        let resolver = MockResolver {
            records: HashMap::from([(
                "example.com".to_string(),
                vec!["some-other-record=xyz".to_string()],
            )]),
        };

        assert!(!verify_domain(&resolver, "example.com", &token)
            .await
            .expect("verification should succeed"));
    }

    #[tokio::test]
    async fn verify_domain_rejects_wrong_domain() {
        let token = generate_verification_token();
        let expected = build_txt_record_value(&token);
        let resolver = MockResolver {
            records: HashMap::from([("example.com".to_string(), vec![expected])]),
        };

        assert!(!verify_domain(&resolver, "other.com", &token)
            .await
            .expect("verification should succeed"));
    }

    #[tokio::test]
    async fn verify_domain_trims_records() {
        let token = generate_verification_token();
        let expected = build_txt_record_value(&token);
        let resolver = MockResolver {
            records: HashMap::from([(
                "example.com".to_string(),
                vec![format!("  {expected}  ")],
            )]),
        };

        assert!(verify_domain(&resolver, "example.com", &token)
            .await
            .expect("verification should succeed"));
    }

    #[tokio::test]
    async fn verify_domain_matches_among_multiple_records() {
        let token = generate_verification_token();
        let expected = build_txt_record_value(&token);
        let resolver = MockResolver {
            records: HashMap::from([(
                "example.com".to_string(),
                vec![
                    "v=spf1 include:_spf.example.com ~all".to_string(),
                    expected,
                    "google-site-verification=abc".to_string(),
                ],
            )]),
        };

        assert!(verify_domain(&resolver, "example.com", &token)
            .await
            .expect("verification should succeed"));
    }

    #[tokio::test]
    async fn hickory_resolver_new_default_and_lookup_error() {
        let _ = HickoryDnsResolver::new();
        let resolver = HickoryDnsResolver::default();
        let result = resolver.txt_records("does-not-exist.invalid").await;
        assert!(
            result.is_err(),
            "lookup for a non-existent domain should fail"
        );
    }
}
