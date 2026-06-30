//! Home Realm Discovery (HRD) for the universal login flow.
//!
//! `Hrd::discover` takes an email and a `return_to` URL and returns a
//! backend-driven redirect. It is an internal module and is never exposed
//! directly to browsers.

use std::sync::Arc;

use serde_json::Value;
use thiserror::Error;

use crate::db::{
    ConnectionType, DbError, SamlProviderStore, TenantConnectionStore, TenantDomainStore,
};

/// Result of an HRD discovery call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryResult {
    Oidc(OidcRedirect),
    OAuth2(OAuth2Redirect),
    Saml(SamlRedirect),
    SelectTenant(TenantSelectionRedirect),
}

/// Redirect to an OIDC authorization endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcRedirect {
    pub authorization_url: String,
}

/// Redirect to an OAuth2 authorization endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuth2Redirect {
    pub authorization_url: String,
}

/// Redirect to a SAML Identity Provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlRedirect {
    pub sso_url: String,
    pub saml_request: String,
    pub relay_state: String,
}

/// Redirect to the tenant selection page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantSelectionRedirect {
    pub redirect_url: String,
}

/// Errors that can occur during HRD discovery.
#[derive(Debug, Error)]
pub enum HrdError {
    #[error("invalid email")]
    InvalidEmail,

    #[error("missing email")]
    MissingEmail,

    #[error("missing return_to")]
    MissingReturnTo,

    #[error("invalid return_to")]
    InvalidReturnTo,

    #[error("connection disabled")]
    ConnectionDisabled,

    #[error("SAML provider not found")]
    SamlProviderNotFound,

    #[error("invalid connection configuration: {0}")]
    InvalidConnectionConfig(String),

    #[error("database error: {0}")]
    Database(#[from] DbError),
}

impl From<HrdError> for sunbeam_g2v::error::ServiceError {
    fn from(err: HrdError) -> Self {
        match err {
            HrdError::InvalidEmail => Self::InvalidArgument("invalid email".to_string()),
            HrdError::MissingEmail => Self::InvalidArgument("missing email".to_string()),
            HrdError::MissingReturnTo => Self::InvalidArgument("missing return_to".to_string()),
            HrdError::InvalidReturnTo => Self::InvalidArgument("invalid return_to".to_string()),
            HrdError::ConnectionDisabled => {
                Self::PermissionDenied("connection disabled".to_string())
            }
            HrdError::SamlProviderNotFound => {
                Self::NotFound("SAML provider not found".to_string())
            }
            HrdError::InvalidConnectionConfig(msg) => Self::InvalidArgument(msg),
            HrdError::Database(db_err) => db_err.into(),
        }
    }
}

/// Home Realm Discovery service.
pub struct Hrd {
    connections: Arc<dyn TenantConnectionStore>,
    #[allow(dead_code)]
    domains: Arc<dyn TenantDomainStore>,
    saml_providers: Arc<dyn SamlProviderStore>,
    public_base_url: String,
}

impl Hrd {
    /// Create a new HRD service.
    pub fn new(
        connections: Arc<dyn TenantConnectionStore>,
        domains: Arc<dyn TenantDomainStore>,
        saml_providers: Arc<dyn SamlProviderStore>,
        public_base_url: String,
    ) -> Self {
        Self {
            connections,
            domains,
            saml_providers,
            public_base_url,
        }
    }

    /// Discover the authentication method for an email address.
    pub async fn discover(
        &self,
        email: &str,
        return_to: &str,
    ) -> Result<DiscoveryResult, HrdError> {
        validate_email(email)?;
        validate_return_to(return_to)?;

        let domain = email
            .rsplit_once('@')
            .map(|(_, d)| d)
            .unwrap_or_default();

        match self.connections.get_by_domain(domain).await {
            Ok(connection) => match connection.connection_type {
                ConnectionType::Oidc => {
                    let url = build_oidc_url(&connection.config, return_to)?;
                    Ok(DiscoveryResult::Oidc(OidcRedirect { authorization_url: url }))
                }
                ConnectionType::OAuth2 => {
                    let url = build_oauth2_url(&connection.config, return_to)?;
                    Ok(DiscoveryResult::OAuth2(OAuth2Redirect {
                        authorization_url: url,
                    }))
                }
                ConnectionType::Saml => {
                    let redirect = build_saml_redirect(
                        &connection.tenant_id,
                        &connection.config,
                        return_to,
                        &*self.saml_providers,
                    )
                    .await?;
                    Ok(DiscoveryResult::Saml(redirect))
                }
            },
            Err(DbError::ConnectionNotFound) => Ok(DiscoveryResult::SelectTenant(
                TenantSelectionRedirect {
                    redirect_url: build_select_tenant_url(
                        &self.public_base_url,
                        email,
                        return_to,
                    ),
                },
            )),
            Err(e) => Err(HrdError::Database(e)),
        }
    }
}

fn validate_email(email: &str) -> Result<(), HrdError> {
    if email.is_empty() {
        return Err(HrdError::MissingEmail);
    }
    if email.chars().filter(|&c| c == '@').count() != 1 {
        return Err(HrdError::InvalidEmail);
    }
    let domain = email
        .rsplit_once('@')
        .map(|(_, d)| d)
        .unwrap_or_default();
    if domain.is_empty() {
        return Err(HrdError::InvalidEmail);
    }
    Ok(())
}

fn validate_return_to(return_to: &str) -> Result<(), HrdError> {
    if return_to.is_empty() {
        return Err(HrdError::MissingReturnTo);
    }
    if url::Url::parse(return_to).is_err() {
        return Err(HrdError::InvalidReturnTo);
    }
    Ok(())
}

fn build_select_tenant_url(base_url: &str, email: &str, return_to: &str) -> String {
    format!(
        "{}/login/select-tenant?email={}&return_to={}",
        base_url.trim_end_matches('/'),
        urlencoding::encode(email),
        urlencoding::encode(return_to),
    )
}

fn build_oidc_url(config: &Value, _return_to: &str) -> Result<String, HrdError> {
    let issuer = config["issuer"]
        .as_str()
        .ok_or_else(|| HrdError::InvalidConnectionConfig("missing issuer".to_string()))?;
    let client_id = config["client_id"]
        .as_str()
        .ok_or_else(|| HrdError::InvalidConnectionConfig("missing client_id".to_string()))?;
    let redirect_uri = config["redirect_uri"]
        .as_str()
        .ok_or_else(|| HrdError::InvalidConnectionConfig("missing redirect_uri".to_string()))?;
    let scopes: Vec<&str> = config["scopes"]
        .as_array()
        .ok_or_else(|| HrdError::InvalidConnectionConfig("missing scopes".to_string()))?
        .iter()
        .filter_map(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .collect();
    if scopes.is_empty() {
        return Err(HrdError::InvalidConnectionConfig("empty scopes".to_string()));
    }

    let issuer_url = normalize_issuer_url(issuer);
    let state = generate_state();

    Ok(format!(
        "{issuer_url}/oauth2/authorize?client_id={}&response_type=code&scope={}&redirect_uri={}&state={}",
        urlencoding::encode(client_id),
        urlencoding::encode(&scopes.join(" ")),
        urlencoding::encode(redirect_uri),
        urlencoding::encode(&state),
    ))
}

fn build_oauth2_url(config: &Value, _return_to: &str) -> Result<String, HrdError> {
    let authorization_url = config["authorization_url"].as_str().ok_or_else(|| {
        HrdError::InvalidConnectionConfig("missing authorization_url".to_string())
    })?;
    let client_id = config["client_id"]
        .as_str()
        .ok_or_else(|| HrdError::InvalidConnectionConfig("missing client_id".to_string()))?;
    let redirect_uri = config["redirect_uri"]
        .as_str()
        .ok_or_else(|| HrdError::InvalidConnectionConfig("missing redirect_uri".to_string()))?;
    let scopes: Vec<&str> = config["scopes"]
        .as_array()
        .ok_or_else(|| HrdError::InvalidConnectionConfig("missing scopes".to_string()))?
        .iter()
        .filter_map(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .collect();
    if scopes.is_empty() {
        return Err(HrdError::InvalidConnectionConfig("empty scopes".to_string()));
    }

    let state = generate_state();

    Ok(format!(
        "{authorization_url}?client_id={}&response_type=code&scope={}&redirect_uri={}&state={}",
        urlencoding::encode(client_id),
        urlencoding::encode(&scopes.join(" ")),
        urlencoding::encode(redirect_uri),
        urlencoding::encode(&state),
    ))
}

async fn build_saml_redirect(
    _tenant_id: &str,
    config: &Value,
    _return_to: &str,
    saml_provider_store: &dyn SamlProviderStore,
) -> Result<SamlRedirect, HrdError> {
    let provider_id = config["provider_id"]
        .as_str()
        .ok_or_else(|| HrdError::InvalidConnectionConfig("missing provider_id".to_string()))?;
    let provider = saml_provider_store
        .get_by_id(provider_id)
        .await
        .map_err(|e| match e {
            DbError::SamlProviderNotFound => HrdError::SamlProviderNotFound,
            _ => HrdError::Database(e),
        })?;

    Ok(SamlRedirect {
        sso_url: provider.idp_sso_url,
        saml_request: String::new(),
        relay_state: String::new(),
    })
}

fn normalize_issuer_url(issuer: &str) -> String {
    if issuer.starts_with("https://") || issuer.starts_with("http://") {
        issuer.trim_end_matches('/').to_string()
    } else {
        format!("https://{issuer}")
    }
}

fn generate_state() -> String {
    let bytes: [u8; 32] = rand::random();
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;

    use super::*;
    use crate::db::{
        SamlProviderRow, TenantConnectionRow, TenantConnectionStore, TenantDomainRow,
        TenantDomainStore,
    };

    struct MockTenantConnectionStore {
        connections: Mutex<HashMap<String, TenantConnectionRow>>,
    }

    #[async_trait]
    impl TenantConnectionStore for MockTenantConnectionStore {
        async fn create(
            &self,
            _tenant_id: &str,
            _connection_type: ConnectionType,
            _domain: &str,
            _config: Value,
        ) -> Result<TenantConnectionRow, DbError> {
            unimplemented!()
        }

        async fn get_by_domain(&self, domain: &str) -> Result<TenantConnectionRow, DbError> {
            let connections = self.connections.lock().unwrap();
            connections
                .get(domain)
                .cloned()
                .filter(|c| c.is_enabled)
                .ok_or(DbError::ConnectionNotFound)
        }

        async fn get_by_id(
            &self,
            _tenant_id: &str,
            _id: &str,
        ) -> Result<TenantConnectionRow, DbError> {
            unimplemented!()
        }

        async fn list_by_tenant(
            &self,
            _tenant_id: &str,
        ) -> Result<Vec<TenantConnectionRow>, DbError> {
            unimplemented!()
        }

        async fn update_config(
            &self,
            _tenant_id: &str,
            _id: &str,
            _config: Value,
        ) -> Result<TenantConnectionRow, DbError> {
            unimplemented!()
        }

        async fn set_enabled(
            &self,
            _tenant_id: &str,
            _id: &str,
            _is_enabled: bool,
        ) -> Result<TenantConnectionRow, DbError> {
            unimplemented!()
        }
    }

    struct MockTenantDomainStore;

    #[async_trait]
    impl TenantDomainStore for MockTenantDomainStore {
        async fn create(&self, _tenant_id: &str, _domain: &str) -> Result<TenantDomainRow, DbError> {
            unimplemented!()
        }

        async fn get_by_domain(&self, _domain: &str) -> Result<TenantDomainRow, DbError> {
            unimplemented!()
        }

        async fn mark_verified(
            &self,
            _tenant_id: &str,
            _id: &str,
        ) -> Result<TenantDomainRow, DbError> {
            unimplemented!()
        }

        async fn list_by_tenant(
            &self,
            _tenant_id: &str,
        ) -> Result<Vec<TenantDomainRow>, DbError> {
            unimplemented!()
        }
    }

    struct MockSamlProviderStore {
        providers: Mutex<HashMap<String, SamlProviderRow>>,
    }

    #[async_trait]
    impl SamlProviderStore for MockSamlProviderStore {
        #[allow(clippy::too_many_arguments)]
        async fn create(
            &self,
            _tenant_id: &str,
            _name: &str,
            _idp_entity_id: &str,
            _idp_sso_url: &str,
            _idp_certificate_pem: Option<&str>,
            _sp_entity_id: &str,
            _acs_url: &str,
            _name_id_format: Option<&str>,
            _schema_id: &str,
            _authn_requests_signed: bool,
        ) -> Result<SamlProviderRow, DbError> {
            unimplemented!()
        }

        async fn get(&self, _tenant_id: &str, _id: &str) -> Result<SamlProviderRow, DbError> {
            unimplemented!()
        }

        async fn get_by_id(&self, id: &str) -> Result<SamlProviderRow, DbError> {
            let providers = self.providers.lock().unwrap();
            providers
                .get(id)
                .cloned()
                .ok_or(DbError::SamlProviderNotFound)
        }
    }

    fn connection_row(
        domain: &str,
        connection_type: ConnectionType,
        config: Value,
        enabled: bool,
    ) -> TenantConnectionRow {
        TenantConnectionRow {
            id: "CONN01".to_string(),
            tenant_id: "TENANT01".to_string(),
            connection_type,
            domain: domain.to_string(),
            config,
            is_enabled: enabled,
            created_at: time::OffsetDateTime::now_utc(),
            updated_at: time::OffsetDateTime::now_utc(),
        }
    }

    fn saml_provider_row(id: &str, sso_url: &str) -> SamlProviderRow {
        SamlProviderRow {
            id: id.to_string(),
            tenant_id: "TENANT01".to_string(),
            name: "Test IdP".to_string(),
            idp_entity_id: "https://idp.example.com".to_string(),
            idp_sso_url: sso_url.to_string(),
            idp_certificate_pem: None,
            sp_entity_id: "https://sp.example.com".to_string(),
            acs_url: "https://sp.example.com/acs".to_string(),
            name_id_format: None,
            schema_id: "SCHEMA01".to_string(),
            authn_requests_signed: false,
            created_at: time::OffsetDateTime::now_utc(),
            updated_at: time::OffsetDateTime::now_utc(),
        }
    }

    fn hrd_with_connection(
        connection: TenantConnectionRow,
        providers: HashMap<String, SamlProviderRow>,
    ) -> Hrd {
        let mut connections = HashMap::new();
        connections.insert(connection.domain.clone(), connection);
        Hrd::new(
            Arc::new(MockTenantConnectionStore {
                connections: Mutex::new(connections),
            }),
            Arc::new(MockTenantDomainStore),
            Arc::new(MockSamlProviderStore {
                providers: Mutex::new(providers),
            }),
            "https://gateway.example.com".to_string(),
        )
    }

    fn empty_hrd() -> Hrd {
        Hrd::new(
            Arc::new(MockTenantConnectionStore {
                connections: Mutex::new(HashMap::new()),
            }),
            Arc::new(MockTenantDomainStore),
            Arc::new(MockSamlProviderStore {
                providers: Mutex::new(HashMap::new()),
            }),
            "https://gateway.example.com".to_string(),
        )
    }

    #[tokio::test]
    async fn discover_oidc_connection_returns_oidc_redirect() {
        let config = serde_json::json!({
            "issuer": "accounts.google.com",
            "client_id": "client123",
            "client_secret": "secret",
            "scopes": ["openid", "email"],
            "redirect_uri": "https://gateway.example.com/auth/callback/oidc",
        });
        let hrd = hrd_with_connection(
            connection_row("example.com", ConnectionType::Oidc, config, true),
            HashMap::new(),
        );

        let result = hrd
            .discover("alice@example.com", "https://app.example.com")
            .await
            .unwrap();

        let url = match result {
            DiscoveryResult::Oidc(OidcRedirect { authorization_url }) => authorization_url,
            other => panic!("expected OIDC redirect, got {other:?}"),
        };
        assert!(url.starts_with("https://accounts.google.com/oauth2/authorize?"));
        assert!(url.contains("client_id=client123"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("scope=openid%20email"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fgateway.example.com%2Fauth%2Fcallback%2Foidc"));
        assert!(url.contains("state="));
    }

    #[tokio::test]
    async fn discover_oauth2_connection_returns_oauth2_redirect() {
        let config = serde_json::json!({
            "authorization_url": "https://github.com/login/oauth/authorize",
            "token_url": "https://github.com/login/oauth/access_token",
            "userinfo_url": "https://api.github.com/user",
            "userinfo_email_path": "email",
            "client_id": "client456",
            "client_secret": "secret",
            "scopes": ["user:email"],
            "redirect_uri": "https://gateway.example.com/auth/callback/oauth2",
        });
        let hrd = hrd_with_connection(
            connection_row("example.com", ConnectionType::OAuth2, config, true),
            HashMap::new(),
        );

        let result = hrd
            .discover("alice@example.com", "https://app.example.com")
            .await
            .unwrap();

        let url = match result {
            DiscoveryResult::OAuth2(OAuth2Redirect { authorization_url }) => authorization_url,
            other => panic!("expected OAuth2 redirect, got {other:?}"),
        };
        assert!(url.starts_with("https://github.com/login/oauth/authorize?"));
        assert!(url.contains("client_id=client456"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("scope=user%3Aemail"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fgateway.example.com%2Fauth%2Fcallback%2Foauth2"));
        assert!(url.contains("state="));
    }

    #[tokio::test]
    async fn discover_saml_connection_returns_saml_redirect() {
        let config = serde_json::json!({ "provider_id": "PROVIDER01" });
        let mut providers = HashMap::new();
        providers.insert(
            "PROVIDER01".to_string(),
            saml_provider_row("PROVIDER01", "https://idp.example.com/saml/sso"),
        );
        let hrd = hrd_with_connection(
            connection_row("example.com", ConnectionType::Saml, config, true),
            providers,
        );

        let result = hrd
            .discover("alice@example.com", "https://app.example.com")
            .await
            .unwrap();

        match result {
            DiscoveryResult::Saml(SamlRedirect {
                sso_url,
                saml_request,
                relay_state,
            }) => {
                assert_eq!(sso_url, "https://idp.example.com/saml/sso");
                assert!(saml_request.is_empty());
                assert!(relay_state.is_empty());
            }
            other => panic!("expected SAML redirect, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn discover_unknown_domain_returns_select_tenant() {
        let hrd = empty_hrd();

        let result = hrd
            .discover("alice@unknown.com", "https://app.example.com")
            .await
            .unwrap();

        match result {
            DiscoveryResult::SelectTenant(TenantSelectionRedirect { redirect_url }) => {
                assert_eq!(
                    redirect_url,
                    "https://gateway.example.com/login/select-tenant?email=alice%40unknown.com&return_to=https%3A%2F%2Fapp.example.com"
                );
            }
            other => panic!("expected select tenant redirect, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn discover_consumer_domain_returns_select_tenant() {
        let hrd = empty_hrd();

        let result = hrd
            .discover("alice@gmail.com", "https://app.example.com")
            .await
            .unwrap();

        match result {
            DiscoveryResult::SelectTenant(TenantSelectionRedirect { redirect_url }) => {
                assert_eq!(
                    redirect_url,
                    "https://gateway.example.com/login/select-tenant?email=alice%40gmail.com&return_to=https%3A%2F%2Fapp.example.com"
                );
            }
            other => panic!("expected select tenant redirect, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn discover_disabled_connection_returns_select_tenant() {
        let config = serde_json::json!({
            "issuer": "accounts.google.com",
            "client_id": "client123",
            "client_secret": "secret",
            "scopes": ["openid", "email"],
            "redirect_uri": "https://gateway.example.com/auth/callback/oidc",
        });
        let hrd = hrd_with_connection(
            connection_row("example.com", ConnectionType::Oidc, config, false),
            HashMap::new(),
        );

        let result = hrd
            .discover("alice@example.com", "https://app.example.com")
            .await
            .unwrap();

        assert!(
            matches!(result, DiscoveryResult::SelectTenant(_)),
            "expected select tenant redirect for disabled connection, got {result:?}"
        );
    }

    #[tokio::test]
    async fn discover_missing_email_returns_error() {
        let hrd = empty_hrd();

        let err = hrd
            .discover("", "https://app.example.com")
            .await
            .unwrap_err();

        assert!(matches!(err, HrdError::MissingEmail));
    }

    #[tokio::test]
    async fn discover_invalid_email_missing_at_returns_error() {
        let hrd = empty_hrd();

        let err = hrd
            .discover("alice.example.com", "https://app.example.com")
            .await
            .unwrap_err();

        assert!(matches!(err, HrdError::InvalidEmail));
    }

    #[tokio::test]
    async fn discover_invalid_email_multiple_at_returns_error() {
        let hrd = empty_hrd();

        let err = hrd
            .discover("alice@foo@bar.com", "https://app.example.com")
            .await
            .unwrap_err();

        assert!(matches!(err, HrdError::InvalidEmail));
    }

    #[tokio::test]
    async fn discover_invalid_email_empty_domain_returns_error() {
        let hrd = empty_hrd();

        let err = hrd
            .discover("alice@", "https://app.example.com")
            .await
            .unwrap_err();

        assert!(matches!(err, HrdError::InvalidEmail));
    }

    #[tokio::test]
    async fn discover_missing_return_to_returns_error() {
        let hrd = empty_hrd();

        let err = hrd.discover("alice@example.com", "").await.unwrap_err();

        assert!(matches!(err, HrdError::MissingReturnTo));
    }

    #[tokio::test]
    async fn discover_invalid_return_to_returns_error() {
        let hrd = empty_hrd();

        let err = hrd
            .discover("alice@example.com", "not a url")
            .await
            .unwrap_err();

        assert!(matches!(err, HrdError::InvalidReturnTo));
    }

    #[test]
    fn normalize_issuer_url_strips_https_prefix() {
        assert_eq!(
            normalize_issuer_url("https://accounts.google.com"),
            "https://accounts.google.com"
        );
    }

    #[test]
    fn normalize_issuer_url_adds_https_when_missing() {
        assert_eq!(
            normalize_issuer_url("accounts.google.com"),
            "https://accounts.google.com"
        );
    }

    #[test]
    fn normalize_issuer_url_trims_trailing_slashes() {
        assert_eq!(
            normalize_issuer_url("https://accounts.google.com/"),
            "https://accounts.google.com"
        );
    }

    #[test]
    fn hrd_error_into_service_error_maps_variants() {
        use sunbeam_g2v::error::ServiceError;

        let cases: Vec<(HrdError, ServiceError)> = vec![
            (
                HrdError::InvalidEmail,
                ServiceError::InvalidArgument("invalid email".into()),
            ),
            (
                HrdError::MissingEmail,
                ServiceError::InvalidArgument("missing email".into()),
            ),
            (
                HrdError::MissingReturnTo,
                ServiceError::InvalidArgument("missing return_to".into()),
            ),
            (
                HrdError::InvalidReturnTo,
                ServiceError::InvalidArgument("invalid return_to".into()),
            ),
            (
                HrdError::ConnectionDisabled,
                ServiceError::PermissionDenied("connection disabled".into()),
            ),
            (
                HrdError::SamlProviderNotFound,
                ServiceError::NotFound("SAML provider not found".into()),
            ),
            (
                HrdError::InvalidConnectionConfig("bad".into()),
                ServiceError::InvalidArgument("bad".into()),
            ),
        ];
        for (err, expected) in cases {
            let actual: ServiceError = err.into();
            assert_eq!(
                std::mem::discriminant(&actual),
                std::mem::discriminant(&expected)
            );
        }
    }
}
