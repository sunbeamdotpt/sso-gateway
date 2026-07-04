use std::net::SocketAddr;

use thiserror::Error;

#[derive(Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub system_tenant_ulid: String,
    pub database_url: String,
    pub hydra_admin_url: String,
    pub hydra_public_url: String,
    pub kratos_admin_url: String,
    pub kratos_public_url: String,
    pub keto_read_url: String,
    pub keto_write_url: String,
    pub public_base_url: String,
    pub ui_public_url: String,
    pub saml_sp_private_key_pem_path: Option<String>,
    pub saml_sp_certificate_pem_path: Option<String>,
    pub saml_idp_entity_id: Option<String>,
    pub saml_request_ttl_seconds: u64,
    pub saml_require_signed_assertions: bool,
    pub saml_require_signed_responses: bool,
    pub registration_enabled: bool,
    pub allowed_return_to_hosts: Vec<String>,
    pub system_bootstrap_client_id: Option<String>,
    pub system_bootstrap_client_secret: Option<String>,
    pub state_cookie_secret: Vec<u8>,
    pub cookie_secure: bool,
    pub cookie_samesite: String,
    pub saml_idp_key_encryption_key: Option<Vec<u8>>,
    pub tenant_connection_encryption_key: Option<Vec<u8>>,
    pub database_ssl_required: bool,
    pub database_max_connections: u32,
    pub database_acquire_timeout_seconds: u64,
    pub database_idle_timeout_seconds: u64,
    pub database_max_lifetime_seconds: u64,
    pub database_statement_timeout_seconds: u64,
    pub token_introspection_cache_ttl_seconds: u64,
    pub session_ttl_seconds: u64,
    pub public_rate_limit_requests: u32,
    pub public_rate_limit_window_seconds: u64,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("bind_addr", &self.bind_addr)
            .field("system_tenant_ulid", &self.system_tenant_ulid)
            .field("database_url", &"[REDACTED]")
            .field("hydra_admin_url", &self.hydra_admin_url)
            .field("hydra_public_url", &self.hydra_public_url)
            .field("kratos_admin_url", &self.kratos_admin_url)
            .field("kratos_public_url", &self.kratos_public_url)
            .field("keto_read_url", &self.keto_read_url)
            .field("keto_write_url", &self.keto_write_url)
            .field("public_base_url", &self.public_base_url)
            .field("ui_public_url", &self.ui_public_url)
            .field(
                "saml_sp_private_key_pem_path",
                &self.saml_sp_private_key_pem_path,
            )
            .field(
                "saml_sp_certificate_pem_path",
                &self.saml_sp_certificate_pem_path,
            )
            .field("saml_idp_entity_id", &self.saml_idp_entity_id)
            .field("saml_request_ttl_seconds", &self.saml_request_ttl_seconds)
            .field(
                "saml_require_signed_assertions",
                &self.saml_require_signed_assertions,
            )
            .field(
                "saml_require_signed_responses",
                &self.saml_require_signed_responses,
            )
            .field("registration_enabled", &self.registration_enabled)
            .field("allowed_return_to_hosts", &self.allowed_return_to_hosts)
            .field(
                "system_bootstrap_client_id",
                &self.system_bootstrap_client_id,
            )
            .field("system_bootstrap_client_secret", &"[REDACTED]")
            .field("state_cookie_secret", &"[REDACTED]")
            .field("cookie_secure", &self.cookie_secure)
            .field("cookie_samesite", &self.cookie_samesite)
            .field(
                "saml_idp_key_encryption_key",
                &self
                    .saml_idp_key_encryption_key
                    .as_ref()
                    .map(|_| "[REDACTED]"),
            )
            .field(
                "tenant_connection_encryption_key",
                &self
                    .tenant_connection_encryption_key
                    .as_ref()
                    .map(|_| "[REDACTED]"),
            )
            .field("database_ssl_required", &self.database_ssl_required)
            .field("database_max_connections", &self.database_max_connections)
            .field(
                "database_acquire_timeout_seconds",
                &self.database_acquire_timeout_seconds,
            )
            .field(
                "database_idle_timeout_seconds",
                &self.database_idle_timeout_seconds,
            )
            .field(
                "database_max_lifetime_seconds",
                &self.database_max_lifetime_seconds,
            )
            .field(
                "database_statement_timeout_seconds",
                &self.database_statement_timeout_seconds,
            )
            .field(
                "token_introspection_cache_ttl_seconds",
                &self.token_introspection_cache_ttl_seconds,
            )
            .field("session_ttl_seconds", &self.session_ttl_seconds)
            .field(
                "public_rate_limit_requests",
                &self.public_rate_limit_requests,
            )
            .field(
                "public_rate_limit_window_seconds",
                &self.public_rate_limit_window_seconds,
            )
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing environment variable: {0}")]
    MissingVar(String),

    #[error("invalid bind address: {0}")]
    InvalidBindAddr(#[from] std::net::AddrParseError),

    #[error("invalid system tenant ulid: {0}")]
    InvalidSystemTenantUlid(String),

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("invalid base64: {0}")]
    InvalidBase64(#[from] base64::DecodeError),
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let system_tenant_ulid = std::env::var("SYSTEM_TENANT_ULID")
            .map_err(|_| ConfigError::MissingVar("SYSTEM_TENANT_ULID".to_string()))?;

        if ulid::Ulid::from_string(&system_tenant_ulid).is_err() {
            return Err(ConfigError::InvalidSystemTenantUlid(system_tenant_ulid));
        }

        let public_base_url = std::env::var("PUBLIC_BASE_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());

        let ui_public_url =
            std::env::var("UI_PUBLIC_URL").unwrap_or_else(|_| public_base_url.clone());

        let mut allowed_return_to_hosts: Vec<String> = std::env::var("ALLOWED_RETURN_TO_HOSTS")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|h| h.trim().to_string())
                    .filter(|h| !h.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        if allowed_return_to_hosts.is_empty()
            && let Some(host) = Self::default_return_to_host(&public_base_url)
        {
            allowed_return_to_hosts.push(host);
        }

        if allowed_return_to_hosts.is_empty() {
            return Err(ConfigError::InvalidConfig(
                "ALLOWED_RETURN_TO_HOSTS must contain at least one host or PUBLIC_BASE_URL must be a valid URL".to_string(),
            ));
        }

        let state_cookie_secret = std::env::var("STATE_COOKIE_SECRET")
            .map_err(|_| ConfigError::MissingVar("STATE_COOKIE_SECRET".to_string()))?
            .into_bytes();
        if state_cookie_secret.len() < 32 {
            return Err(ConfigError::InvalidConfig(
                "STATE_COOKIE_SECRET must be at least 32 bytes".to_string(),
            ));
        }

        let system_bootstrap_client_secret = std::env::var("SYSTEM_BOOTSTRAP_CLIENT_SECRET").ok();

        Self::validate_no_dev_secrets(
            &state_cookie_secret,
            system_bootstrap_client_secret.as_deref(),
        )?;

        let cookie_secure = std::env::var("COOKIE_SECURE")
            .ok()
            .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
            .unwrap_or_else(|| public_base_url.starts_with("https://"));

        // The gateway session cookie uses the __Host- prefix, which requires the
        // Secure attribute.
        const SESSION_COOKIE_NAME: &str = "__Host-sso_session";
        if SESSION_COOKIE_NAME.starts_with("__Host-") && !cookie_secure {
            return Err(ConfigError::InvalidConfig(
                "COOKIE_SECURE must be true because the session cookie uses the __Host- prefix"
                    .to_string(),
            ));
        }

        let database_url = std::env::var("DATABASE_URL")
            .map_err(|_| ConfigError::MissingVar("DATABASE_URL".to_string()))?;
        let database_ssl_required = std::env::var("DATABASE_SSL_REQUIRED")
            .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
            .unwrap_or(true);
        if database_ssl_required && database_url.contains("sslmode=disable") {
            return Err(ConfigError::InvalidConfig(
                "DATABASE_URL uses sslmode=disable but DATABASE_SSL_REQUIRED is true".to_string(),
            ));
        }

        let saml_idp_key_encryption_key =
            Self::parse_optional_base64_key("SAML_IDP_KEY_ENCRYPTION_KEY")?;
        let tenant_connection_encryption_key =
            Self::parse_optional_base64_key("TENANT_CONNECTION_ENCRYPTION_KEY")?;

        Ok(Self {
            bind_addr: std::env::var("BIND_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
                .parse()?,
            system_tenant_ulid,
            database_url,
            hydra_admin_url: std::env::var("HYDRA_ADMIN_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:4445".to_string()),
            hydra_public_url: std::env::var("HYDRA_PUBLIC_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:4444".to_string()),
            kratos_admin_url: std::env::var("KRATOS_ADMIN_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:4434".to_string()),
            kratos_public_url: std::env::var("KRATOS_PUBLIC_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:4433".to_string()),
            keto_read_url: std::env::var("KETO_READ_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:4466".to_string()),
            keto_write_url: std::env::var("KETO_WRITE_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:4467".to_string()),
            public_base_url,
            ui_public_url,
            saml_sp_private_key_pem_path: std::env::var("SAML_SP_PRIVATE_KEY_PEM_PATH").ok(),
            saml_sp_certificate_pem_path: std::env::var("SAML_SP_CERTIFICATE_PEM_PATH").ok(),
            saml_idp_entity_id: std::env::var("SAML_IDP_ENTITY_ID").ok(),
            saml_request_ttl_seconds: std::env::var("SAML_REQUEST_TTL_SECONDS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(900),
            saml_require_signed_assertions: std::env::var("SAML_REQUIRE_SIGNED_ASSERTIONS")
                .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
                .unwrap_or(true),
            saml_require_signed_responses: std::env::var("SAML_REQUIRE_SIGNED_RESPONSES")
                .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            registration_enabled: std::env::var("REGISTRATION_ENABLED")
                .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            allowed_return_to_hosts,
            system_bootstrap_client_id: std::env::var("SYSTEM_BOOTSTRAP_CLIENT_ID").ok(),
            system_bootstrap_client_secret,
            state_cookie_secret,
            cookie_secure,
            cookie_samesite: std::env::var("COOKIE_SAMESITE").unwrap_or_else(|_| "Lax".to_string()),
            saml_idp_key_encryption_key,
            tenant_connection_encryption_key,
            database_ssl_required,
            database_max_connections: std::env::var("DATABASE_MAX_CONNECTIONS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(25),
            database_acquire_timeout_seconds: std::env::var("DATABASE_ACQUIRE_TIMEOUT_SECONDS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10),
            database_idle_timeout_seconds: std::env::var("DATABASE_IDLE_TIMEOUT_SECONDS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(600),
            database_max_lifetime_seconds: std::env::var("DATABASE_MAX_LIFETIME_SECONDS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1800),
            database_statement_timeout_seconds: std::env::var("DATABASE_STATEMENT_TIMEOUT_SECONDS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
            token_introspection_cache_ttl_seconds: std::env::var(
                "TOKEN_INTROSPECTION_CACHE_TTL_SECONDS",
            )
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30),
            session_ttl_seconds: std::env::var("SESSION_TTL_SECONDS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(86400),
            public_rate_limit_requests: std::env::var("PUBLIC_RATE_LIMIT_REQUESTS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100),
            public_rate_limit_window_seconds: std::env::var("PUBLIC_RATE_LIMIT_WINDOW_SECONDS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(60),
        })
    }

    fn default_return_to_host(public_base_url: &str) -> Option<String> {
        public_base_url
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .and_then(|host_port| {
                let host = host_port.split(':').next()?;
                if host.is_empty() || host == "127.0.0.1" || host == "localhost" {
                    None
                } else {
                    Some(host.to_string())
                }
            })
    }

    fn parse_optional_base64_key(var: &str) -> Result<Option<Vec<u8>>, ConfigError> {
        let Some(value) = std::env::var(var).ok() else {
            return Ok(None);
        };
        let decoded =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value.trim())
                .or_else(|_| {
                    base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE, value.trim())
                })
                .map_err(|_| ConfigError::InvalidConfig(format!("{var} is not valid base64")))?;
        if decoded.len() < 32 {
            return Err(ConfigError::InvalidConfig(format!(
                "{var} must decode to at least 32 bytes"
            )));
        }
        Ok(Some(decoded))
    }

    fn validate_no_dev_secrets(
        state_cookie_secret: &[u8],
        system_bootstrap_client_secret: Option<&str>,
    ) -> Result<(), ConfigError> {
        const DENYLIST: &[&str] = &[
            "youReallyNeedToChangeThis",
            "change-me-in-production-cookie-secret",
            "ory",
            "system-bootstrap-secret",
        ];

        for denied in DENYLIST {
            if state_cookie_secret == denied.as_bytes() {
                return Err(ConfigError::InvalidConfig(format!(
                    "STATE_COOKIE_SECRET must not be the development value '{denied}'"
                )));
            }
            if system_bootstrap_client_secret == Some(*denied) {
                return Err(ConfigError::InvalidConfig(format!(
                    "SYSTEM_BOOTSTRAP_CLIENT_SECRET must not be the development value '{denied}'"
                )));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    // Environment tests are serialized so they do not race on process-global env.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn valid_ulid() -> String {
        ulid::Ulid::new().to_string()
    }

    fn set_env(key: &str, value: &str) {
        // Environment manipulation in tests is intentionally serialized by the
        // test runner per process; the unsafe block is required in Rust 2024.
        unsafe { std::env::set_var(key, value) };
    }

    fn clear_env(key: &str) {
        unsafe { std::env::remove_var(key) };
    }

    fn clear_all_config_env() {
        clear_env("SYSTEM_TENANT_ULID");
        clear_env("DATABASE_URL");
        clear_env("BIND_ADDR");
        clear_env("HYDRA_ADMIN_URL");
        clear_env("HYDRA_PUBLIC_URL");
        clear_env("KRATOS_ADMIN_URL");
        clear_env("KRATOS_PUBLIC_URL");
        clear_env("KETO_READ_URL");
        clear_env("KETO_WRITE_URL");
        clear_env("PUBLIC_BASE_URL");
        clear_env("SAML_IDP_ENTITY_ID");
        clear_env("SAML_REQUEST_TTL_SECONDS");
        clear_env("SAML_REQUIRE_SIGNED_ASSERTIONS");
        clear_env("SAML_REQUIRE_SIGNED_RESPONSES");
        clear_env("REGISTRATION_ENABLED");
        clear_env("ALLOWED_RETURN_TO_HOSTS");
        clear_env("SYSTEM_BOOTSTRAP_CLIENT_ID");
        clear_env("SYSTEM_BOOTSTRAP_CLIENT_SECRET");
        clear_env("STATE_COOKIE_SECRET");
        clear_env("COOKIE_SECURE");
        clear_env("COOKIE_SAMESITE");
        clear_env("SAML_IDP_KEY_ENCRYPTION_KEY");
        clear_env("TENANT_CONNECTION_ENCRYPTION_KEY");
        clear_env("DATABASE_SSL_REQUIRED");
        clear_env("DATABASE_MAX_CONNECTIONS");
        clear_env("DATABASE_ACQUIRE_TIMEOUT_SECONDS");
        clear_env("DATABASE_IDLE_TIMEOUT_SECONDS");
        clear_env("DATABASE_MAX_LIFETIME_SECONDS");
        clear_env("DATABASE_STATEMENT_TIMEOUT_SECONDS");
        clear_env("TOKEN_INTROSPECTION_CACHE_TTL_SECONDS");
        clear_env("SESSION_TTL_SECONDS");
        clear_env("PUBLIC_RATE_LIMIT_REQUESTS");
        clear_env("PUBLIC_RATE_LIMIT_WINDOW_SECONDS");
        clear_env("UI_PUBLIC_URL");
    }

    #[test]
    fn config_from_env_uses_defaults() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all_config_env();
        let ulid = valid_ulid();
        set_env("SYSTEM_TENANT_ULID", &ulid);
        set_env("DATABASE_URL", "postgres://u:p@localhost/db");
        set_env(
            "STATE_COOKIE_SECRET",
            "test-secret-key-that-is-at-least-32-bytes-long",
        );
        set_env("ALLOWED_RETURN_TO_HOSTS", "example.com");
        set_env("COOKIE_SECURE", "true");

        let config = Config::from_env().expect("config should parse");
        drop(_guard);
        assert_eq!(config.bind_addr, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(config.system_tenant_ulid, ulid);
        assert_eq!(config.database_url, "postgres://u:p@localhost/db");
        assert_eq!(config.hydra_admin_url, "http://127.0.0.1:4445");
        assert_eq!(config.hydra_public_url, "http://127.0.0.1:4444");
        assert_eq!(config.kratos_admin_url, "http://127.0.0.1:4434");
        assert_eq!(config.kratos_public_url, "http://127.0.0.1:4433");
        assert_eq!(config.keto_read_url, "http://127.0.0.1:4466");
        assert_eq!(config.keto_write_url, "http://127.0.0.1:4467");
        assert_eq!(config.public_base_url, "http://127.0.0.1:8080");
        assert_eq!(config.ui_public_url, "http://127.0.0.1:8080");
        assert_eq!(config.saml_idp_entity_id, None);
        assert_eq!(config.saml_request_ttl_seconds, 900);
        assert_eq!(config.session_ttl_seconds, 86400);
        assert_eq!(config.public_rate_limit_requests, 100);
        assert_eq!(config.public_rate_limit_window_seconds, 60);
        assert!(config.saml_require_signed_assertions);
        assert!(!config.saml_require_signed_responses);
        assert!(!config.registration_enabled);
        assert_eq!(
            config.allowed_return_to_hosts,
            vec!["example.com".to_string()]
        );
    }

    #[test]
    fn config_from_env_uses_overrides() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all_config_env();
        let ulid = valid_ulid();
        set_env("SYSTEM_TENANT_ULID", &ulid);
        set_env("DATABASE_URL", "postgres://u:p@localhost/db");
        set_env("BIND_ADDR", "0.0.0.0:3000");
        set_env("HYDRA_ADMIN_URL", "http://hydra:4445");
        set_env("HYDRA_PUBLIC_URL", "http://hydra:4444");
        set_env("KRATOS_ADMIN_URL", "http://kratos:4434");
        set_env("KRATOS_PUBLIC_URL", "http://kratos:4433");
        set_env("KETO_READ_URL", "http://keto:4466");
        set_env("KETO_WRITE_URL", "http://keto:4467");
        set_env("PUBLIC_BASE_URL", "https://gateway.example.com");
        set_env("UI_PUBLIC_URL", "https://ui.example.com");
        set_env("SAML_IDP_ENTITY_ID", "https://idp.example.com");
        set_env("SAML_REQUEST_TTL_SECONDS", "600");
        set_env("SAML_REQUIRE_SIGNED_ASSERTIONS", "false");
        set_env("SAML_REQUIRE_SIGNED_RESPONSES", "true");
        set_env("REGISTRATION_ENABLED", "true");
        set_env("ALLOWED_RETURN_TO_HOSTS", "example.com, app.example.com");
        set_env("SYSTEM_BOOTSTRAP_CLIENT_ID", "bootstrap-client");
        set_env("SYSTEM_BOOTSTRAP_CLIENT_SECRET", "bootstrap-secret-key");
        set_env(
            "STATE_COOKIE_SECRET",
            "override-secret-key-for-cookies-at-least-32-bytes-long",
        );

        let config = Config::from_env().expect("config should parse");
        drop(_guard);
        assert_eq!(config.system_tenant_ulid, ulid);
        assert_eq!(config.bind_addr, "0.0.0.0:3000".parse().unwrap());
        assert_eq!(config.hydra_admin_url, "http://hydra:4445");
        assert_eq!(config.public_base_url, "https://gateway.example.com");
        assert_eq!(config.ui_public_url, "https://ui.example.com");
        assert_eq!(
            config.saml_idp_entity_id,
            Some("https://idp.example.com".to_string())
        );
        assert_eq!(config.saml_request_ttl_seconds, 600);
        assert!(!config.saml_require_signed_assertions);
        assert!(config.saml_require_signed_responses);
        assert!(config.registration_enabled);
        assert_eq!(
            config.allowed_return_to_hosts,
            vec!["example.com".to_string(), "app.example.com".to_string()]
        );
        assert_eq!(
            config.system_bootstrap_client_id,
            Some("bootstrap-client".to_string())
        );
        assert_eq!(
            config.system_bootstrap_client_secret,
            Some("bootstrap-secret-key".to_string())
        );
    }

    #[test]
    fn config_from_env_rejects_missing_system_tenant() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all_config_env();
        set_env("DATABASE_URL", "postgres://u:p@localhost/db");
        set_env(
            "STATE_COOKIE_SECRET",
            "test-secret-key-that-is-at-least-32-bytes-long",
        );
        let err = Config::from_env().unwrap_err();
        drop(_guard);
        assert!(matches!(err, ConfigError::MissingVar(ref s) if s == "SYSTEM_TENANT_ULID"));
    }

    #[test]
    fn config_from_env_rejects_invalid_system_tenant() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all_config_env();
        set_env("SYSTEM_TENANT_ULID", "not-a-ulid");
        set_env("DATABASE_URL", "postgres://u:p@localhost/db");
        set_env(
            "STATE_COOKIE_SECRET",
            "test-secret-key-that-is-at-least-32-bytes-long",
        );
        let err = Config::from_env().unwrap_err();
        drop(_guard);
        assert!(matches!(err, ConfigError::InvalidSystemTenantUlid(ref s) if s == "not-a-ulid"));
    }

    #[test]
    fn config_from_env_parses_allowed_return_to_hosts() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all_config_env();
        let ulid = valid_ulid();
        set_env("SYSTEM_TENANT_ULID", &ulid);
        set_env("DATABASE_URL", "postgres://u:p@localhost/db");
        set_env("ALLOWED_RETURN_TO_HOSTS", "example.com, , app.example.com,");
        set_env(
            "STATE_COOKIE_SECRET",
            "test-secret-key-that-is-at-least-32-bytes-long",
        );
        set_env("COOKIE_SECURE", "true");

        let config = Config::from_env().expect("config should parse");
        drop(_guard);
        assert_eq!(
            config.allowed_return_to_hosts,
            vec!["example.com".to_string(), "app.example.com".to_string()]
        );
        assert!(!config.registration_enabled);
    }

    #[test]
    fn config_from_env_rejects_invalid_bind_addr() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all_config_env();
        let ulid = valid_ulid();
        set_env("SYSTEM_TENANT_ULID", &ulid);
        set_env("DATABASE_URL", "postgres://u:p@localhost/db");
        set_env("BIND_ADDR", "not-an-address");
        set_env(
            "STATE_COOKIE_SECRET",
            "test-secret-key-that-is-at-least-32-bytes-long",
        );
        set_env("ALLOWED_RETURN_TO_HOSTS", "example.com");
        set_env("COOKIE_SECURE", "true");
        let err = Config::from_env().unwrap_err();
        drop(_guard);
        assert!(matches!(err, ConfigError::InvalidBindAddr(_)));
    }

    #[test]
    fn config_from_env_rejects_short_cookie_secret() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all_config_env();
        let ulid = valid_ulid();
        set_env("SYSTEM_TENANT_ULID", &ulid);
        set_env("DATABASE_URL", "postgres://u:p@localhost/db");
        set_env("STATE_COOKIE_SECRET", "short-secret");
        set_env("ALLOWED_RETURN_TO_HOSTS", "example.com");
        let err = Config::from_env().unwrap_err();
        drop(_guard);
        assert!(
            matches!(err, ConfigError::InvalidConfig(ref s) if s.contains("STATE_COOKIE_SECRET"))
        );
    }

    #[test]
    fn config_from_env_rejects_sslmode_disable_when_required() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all_config_env();
        let ulid = valid_ulid();
        set_env("SYSTEM_TENANT_ULID", &ulid);
        set_env(
            "DATABASE_URL",
            "postgres://u:p@localhost/db?sslmode=disable",
        );
        set_env(
            "STATE_COOKIE_SECRET",
            "test-secret-key-that-is-at-least-32-bytes-long",
        );
        set_env("ALLOWED_RETURN_TO_HOSTS", "example.com");
        set_env("COOKIE_SECURE", "true");
        let err = Config::from_env().unwrap_err();
        drop(_guard);
        assert!(matches!(err, ConfigError::InvalidConfig(ref s) if s.contains("sslmode=disable")));
    }

    #[test]
    fn config_debug_redacts_secrets() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all_config_env();
        let ulid = valid_ulid();
        set_env("SYSTEM_TENANT_ULID", &ulid);
        set_env("DATABASE_URL", "postgres://u:p@localhost/db");
        set_env(
            "STATE_COOKIE_SECRET",
            "test-secret-key-that-is-at-least-32-bytes-long",
        );
        set_env("ALLOWED_RETURN_TO_HOSTS", "example.com");
        set_env("SYSTEM_BOOTSTRAP_CLIENT_SECRET", "bootstrap-secret");
        set_env("COOKIE_SECURE", "true");
        let config = Config::from_env().expect("config should parse");
        let debug = format!("{:?}", config);
        drop(_guard);
        assert!(!debug.contains("postgres://u:p"));
        assert!(!debug.contains("test-secret-key"));
        assert!(!debug.contains("bootstrap-secret"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn config_default_return_to_host_derived_from_public_base_url() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all_config_env();
        let ulid = valid_ulid();
        set_env("SYSTEM_TENANT_ULID", &ulid);
        set_env("DATABASE_URL", "postgres://u:p@localhost/db");
        set_env(
            "STATE_COOKIE_SECRET",
            "test-secret-key-that-is-at-least-32-bytes-long",
        );
        set_env("PUBLIC_BASE_URL", "https://gateway.example.com:8443");
        let config = Config::from_env().expect("config should parse");
        drop(_guard);
        assert_eq!(
            config.allowed_return_to_hosts,
            vec!["gateway.example.com".to_string()]
        );
    }

    #[test]
    fn config_rejects_dev_secrets() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all_config_env();
        let ulid = valid_ulid();
        set_env("SYSTEM_TENANT_ULID", &ulid);
        set_env("DATABASE_URL", "postgres://u:p@localhost/db");
        set_env("ALLOWED_RETURN_TO_HOSTS", "example.com");
        set_env("COOKIE_SECURE", "true");
        set_env(
            "STATE_COOKIE_SECRET",
            "change-me-in-production-cookie-secret",
        );

        let err = Config::from_env().unwrap_err();
        drop(_guard);
        assert!(
            matches!(err, ConfigError::InvalidConfig(ref s) if s.contains("change-me-in-production-cookie-secret")),
        );
    }
}
