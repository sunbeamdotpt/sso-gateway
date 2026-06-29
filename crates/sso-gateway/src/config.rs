use std::net::SocketAddr;

use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub system_tenant_ulid: String,
    pub database_url: String,
    pub redis_url: String,
    pub hydra_admin_url: String,
    pub hydra_public_url: String,
    pub kratos_admin_url: String,
    pub kratos_public_url: String,
    pub keto_read_url: String,
    pub keto_write_url: String,
    pub public_base_url: String,
    pub saml_sp_private_key_pem_path: Option<String>,
    pub saml_sp_certificate_pem_path: Option<String>,
    pub saml_idp_entity_id: Option<String>,
    pub saml_request_ttl_seconds: u64,
    pub saml_require_signed_assertions: bool,
    pub saml_require_signed_responses: bool,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing environment variable: {0}")]
    MissingVar(String),

    #[error("invalid bind address: {0}")]
    InvalidBindAddr(#[from] std::net::AddrParseError),

    #[error("invalid system tenant ulid: {0}")]
    InvalidSystemTenantUlid(String),
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let system_tenant_ulid = std::env::var("SYSTEM_TENANT_ULID")
            .map_err(|_| ConfigError::MissingVar("SYSTEM_TENANT_ULID".to_string()))?;

        if ulid::Ulid::from_string(&system_tenant_ulid).is_err() {
            return Err(ConfigError::InvalidSystemTenantUlid(system_tenant_ulid));
        }

        Ok(Self {
            bind_addr: std::env::var("BIND_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
                .parse()?,
            system_tenant_ulid,
            database_url: std::env::var("DATABASE_URL")
                .map_err(|_| ConfigError::MissingVar("DATABASE_URL".to_string()))?,
            redis_url: std::env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string()),
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
            public_base_url: std::env::var("PUBLIC_BASE_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string()),
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
        })
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

    #[test]
    fn config_from_env_uses_defaults() {
        let _guard = ENV_LOCK.lock().unwrap();
        let ulid = valid_ulid();
        set_env("SYSTEM_TENANT_ULID", &ulid);
        set_env("DATABASE_URL", "postgres://u:p@localhost/db");
        // Clear optional values so defaults are exercised.
        clear_env("BIND_ADDR");
        clear_env("REDIS_URL");
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

        let config = Config::from_env().expect("config should parse");
        drop(_guard);
        assert_eq!(config.bind_addr, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(config.system_tenant_ulid, ulid);
        assert_eq!(config.database_url, "postgres://u:p@localhost/db");
        assert_eq!(config.redis_url, "redis://127.0.0.1:6379");
        assert_eq!(config.hydra_admin_url, "http://127.0.0.1:4445");
        assert_eq!(config.hydra_public_url, "http://127.0.0.1:4444");
        assert_eq!(config.kratos_admin_url, "http://127.0.0.1:4434");
        assert_eq!(config.kratos_public_url, "http://127.0.0.1:4433");
        assert_eq!(config.keto_read_url, "http://127.0.0.1:4466");
        assert_eq!(config.keto_write_url, "http://127.0.0.1:4467");
        assert_eq!(config.public_base_url, "http://127.0.0.1:8080");
        assert_eq!(config.saml_idp_entity_id, None);
        assert_eq!(config.saml_request_ttl_seconds, 900);
        assert!(config.saml_require_signed_assertions);
        assert!(!config.saml_require_signed_responses);
    }

    #[test]
    fn config_from_env_uses_overrides() {
        let _guard = ENV_LOCK.lock().unwrap();
        let ulid = valid_ulid();
        set_env("SYSTEM_TENANT_ULID", &ulid);
        set_env("DATABASE_URL", "postgres://u:p@localhost/db");
        set_env("BIND_ADDR", "0.0.0.0:3000");
        set_env("REDIS_URL", "redis://redis:6379");
        set_env("HYDRA_ADMIN_URL", "http://hydra:4445");
        set_env("HYDRA_PUBLIC_URL", "http://hydra:4444");
        set_env("KRATOS_ADMIN_URL", "http://kratos:4434");
        set_env("KRATOS_PUBLIC_URL", "http://kratos:4433");
        set_env("KETO_READ_URL", "http://keto:4466");
        set_env("KETO_WRITE_URL", "http://keto:4467");
        set_env("PUBLIC_BASE_URL", "https://gateway.example.com");
        set_env("SAML_IDP_ENTITY_ID", "https://idp.example.com");
        set_env("SAML_REQUEST_TTL_SECONDS", "600");
        set_env("SAML_REQUIRE_SIGNED_ASSERTIONS", "false");
        set_env("SAML_REQUIRE_SIGNED_RESPONSES", "true");

        let config = Config::from_env().expect("config should parse");
        drop(_guard);
        assert_eq!(config.system_tenant_ulid, ulid);
        assert_eq!(config.bind_addr, "0.0.0.0:3000".parse().unwrap());
        assert_eq!(config.redis_url, "redis://redis:6379");
        assert_eq!(config.hydra_admin_url, "http://hydra:4445");
        assert_eq!(config.public_base_url, "https://gateway.example.com");
        assert_eq!(config.saml_idp_entity_id, Some("https://idp.example.com".to_string()));
        assert_eq!(config.saml_request_ttl_seconds, 600);
        assert!(!config.saml_require_signed_assertions);
        assert!(config.saml_require_signed_responses);
    }

    #[test]
    fn config_from_env_rejects_missing_system_tenant() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env("SYSTEM_TENANT_ULID");
        set_env("DATABASE_URL", "postgres://u:p@localhost/db");
        let err = Config::from_env().unwrap_err();
        drop(_guard);
        assert!(matches!(err, ConfigError::MissingVar(ref s) if s == "SYSTEM_TENANT_ULID"));
    }

    #[test]
    fn config_from_env_rejects_invalid_system_tenant() {
        let _guard = ENV_LOCK.lock().unwrap();
        set_env("SYSTEM_TENANT_ULID", "not-a-ulid");
        set_env("DATABASE_URL", "postgres://u:p@localhost/db");
        let err = Config::from_env().unwrap_err();
        drop(_guard);
        assert!(
            matches!(err, ConfigError::InvalidSystemTenantUlid(ref s) if s == "not-a-ulid")
        );
    }

    #[test]
    fn config_from_env_rejects_invalid_bind_addr() {
        let _guard = ENV_LOCK.lock().unwrap();
        let ulid = valid_ulid();
        set_env("SYSTEM_TENANT_ULID", &ulid);
        set_env("DATABASE_URL", "postgres://u:p@localhost/db");
        set_env("BIND_ADDR", "not-an-address");
        let err = Config::from_env().unwrap_err();
        drop(_guard);
        assert!(matches!(err, ConfigError::InvalidBindAddr(_)));
    }
}
