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
    pub kratos_default_schema_id: String,
    pub permissions_backend: PermissionsBackend,
    pub keto_read_url: String,
    pub keto_write_url: String,
    pub openfga_url: String,
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
    pub nats_url: Option<String>,
    pub agent_act_token_ttl_seconds: u64,
    pub agent_cache_ttl_seconds: u64,
    pub public_rate_limit_requests: u32,
    pub public_rate_limit_window_seconds: u64,
    pub self_service_paths: SelfServicePaths,
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
            .field("kratos_default_schema_id", &self.kratos_default_schema_id)
            .field("permissions_backend", &self.permissions_backend)
            .field("keto_read_url", &self.keto_read_url)
            .field("keto_write_url", &self.keto_write_url)
            .field("openfga_url", &self.openfga_url)
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
            .field("nats_url", &self.nats_url.as_ref().map(|_| "[REDACTED]"))
            .field(
                "agent_act_token_ttl_seconds",
                &self.agent_act_token_ttl_seconds,
            )
            .field("agent_cache_ttl_seconds", &self.agent_cache_ttl_seconds)
            .field(
                "public_rate_limit_requests",
                &self.public_rate_limit_requests,
            )
            .field(
                "public_rate_limit_window_seconds",
                &self.public_rate_limit_window_seconds,
            )
            .field("self_service_paths", &self.self_service_paths)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionsBackend {
    Keto,
    OpenFga,
}

/// Branded, browser-facing paths for the Kratos self-service surface.
///
/// Every Kratos self-service URL that can reach a browser (flow init
/// redirects, AAL2 upgrades, logout chains, email token links, OIDC
/// callbacks, the WebAuthn script) is rewritten to these gateway paths so no
/// Ory construct leaks into an address bar, redirect chain, or inbox. Each
/// path is independently configurable so downstream deployments can shape
/// their own URL namespace; the gateway rewrites to whatever is configured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelfServicePaths {
    pub login: String,
    pub registration: String,
    pub settings: String,
    pub recovery: String,
    pub verification: String,
    pub logout: String,
    pub errors: String,
    pub oidc_callback: String,
    pub webauthn_js: String,
}

impl Default for SelfServicePaths {
    fn default() -> Self {
        Self {
            login: "/identity/login".to_string(),
            registration: "/identity/registration".to_string(),
            settings: "/identity/settings".to_string(),
            recovery: "/identity/recovery".to_string(),
            verification: "/identity/verification".to_string(),
            logout: "/identity/logout".to_string(),
            errors: "/identity/errors".to_string(),
            oidc_callback: "/identity/oidc/callback".to_string(),
            webauthn_js: "/identity/webauthn.js".to_string(),
        }
    }
}

/// All `SELF_SERVICE_*_PATH` environment variables, for tests and docs.
#[cfg(test)]
pub(crate) const SELF_SERVICE_PATH_VARS: [&str; 9] = [
    "SELF_SERVICE_LOGIN_PATH",
    "SELF_SERVICE_REGISTRATION_PATH",
    "SELF_SERVICE_SETTINGS_PATH",
    "SELF_SERVICE_RECOVERY_PATH",
    "SELF_SERVICE_VERIFICATION_PATH",
    "SELF_SERVICE_LOGOUT_PATH",
    "SELF_SERVICE_ERRORS_PATH",
    "SELF_SERVICE_OIDC_CALLBACK_PATH",
    "SELF_SERVICE_WEBAUTHN_JS_PATH",
];

impl SelfServicePaths {
    /// Prefixes already owned by other gateway surfaces. Branded self-service
    /// paths must not squat on them (and `/self-service` is reserved for the
    /// interim email-link shim).
    const RESERVED_PREFIXES: &'static [&'static str] = &[
        "/oauth2",
        "/saml",
        "/scim",
        "/callbacks",
        "/iam",
        "/.well-known",
        "/health",
        "/self-service",
    ];

    pub fn from_env() -> Result<Self, ConfigError> {
        let defaults = Self::default();
        let paths = Self {
            login: Self::env_or("SELF_SERVICE_LOGIN_PATH", &defaults.login),
            registration: Self::env_or("SELF_SERVICE_REGISTRATION_PATH", &defaults.registration),
            settings: Self::env_or("SELF_SERVICE_SETTINGS_PATH", &defaults.settings),
            recovery: Self::env_or("SELF_SERVICE_RECOVERY_PATH", &defaults.recovery),
            verification: Self::env_or("SELF_SERVICE_VERIFICATION_PATH", &defaults.verification),
            logout: Self::env_or("SELF_SERVICE_LOGOUT_PATH", &defaults.logout),
            errors: Self::env_or("SELF_SERVICE_ERRORS_PATH", &defaults.errors),
            oidc_callback: Self::env_or("SELF_SERVICE_OIDC_CALLBACK_PATH", &defaults.oidc_callback),
            webauthn_js: Self::env_or("SELF_SERVICE_WEBAUTHN_JS_PATH", &defaults.webauthn_js),
        };
        paths.validate()?;
        Ok(paths)
    }

    fn env_or(var: &str, default: &str) -> String {
        std::env::var(var)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| default.to_string())
    }

    /// Every `(env var, configured path)` pair, in a stable order.
    fn vars(&self) -> [(&'static str, &str); 9] {
        [
            ("SELF_SERVICE_LOGIN_PATH", self.login.as_str()),
            ("SELF_SERVICE_REGISTRATION_PATH", self.registration.as_str()),
            ("SELF_SERVICE_SETTINGS_PATH", self.settings.as_str()),
            ("SELF_SERVICE_RECOVERY_PATH", self.recovery.as_str()),
            ("SELF_SERVICE_VERIFICATION_PATH", self.verification.as_str()),
            ("SELF_SERVICE_LOGOUT_PATH", self.logout.as_str()),
            ("SELF_SERVICE_ERRORS_PATH", self.errors.as_str()),
            ("SELF_SERVICE_OIDC_CALLBACK_PATH", self.oidc_callback.as_str()),
            ("SELF_SERVICE_WEBAUTHN_JS_PATH", self.webauthn_js.as_str()),
        ]
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let all = self.vars();
        for (var, path) in &all {
            if !path.starts_with('/') || path.len() == 1 {
                return Err(ConfigError::InvalidConfig(format!(
                    "{var} must be an absolute path below the root, got '{path}'"
                )));
            }
            if path.ends_with('/') || path.contains(['?', '#']) {
                return Err(ConfigError::InvalidConfig(format!(
                    "{var} must be a bare path without trailing slash, query, or fragment, got '{path}'"
                )));
            }
            if Self::RESERVED_PREFIXES
                .iter()
                .any(|prefix| path == prefix || path.starts_with(&format!("{prefix}/")))
            {
                return Err(ConfigError::InvalidConfig(format!(
                    "{var} must not shadow a reserved gateway prefix, got '{path}'"
                )));
            }
        }
        for (index, (var, path)) in all.iter().enumerate() {
            for (other_var, other) in &all[index + 1..] {
                if path == other {
                    return Err(ConfigError::InvalidConfig(format!(
                        "{var} and {other_var} must be distinct, both are '{path}'"
                    )));
                }
            }
            // The OIDC callback also matches `{oidc_callback}/{provider}`, so
            // no other branded path may live underneath it.
            if *path != self.oidc_callback
                && path.starts_with(&format!("{}/", self.oidc_callback))
            {
                return Err(ConfigError::InvalidConfig(format!(
                    "{var} must not live under SELF_SERVICE_OIDC_CALLBACK_PATH, got '{path}'"
                )));
            }
        }
        Ok(())
    }
}

/// Choose the default permissions backend based on compiled features.
/// OpenFGA is preferred when both are available.
pub(crate) fn default_permissions_backend() -> PermissionsBackend {
    #[cfg(feature = "openfga")]
    {
        PermissionsBackend::OpenFga
    }
    #[cfg(not(feature = "openfga"))]
    {
        PermissionsBackend::Keto
    }
}

impl std::str::FromStr for PermissionsBackend {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "keto" => Ok(Self::Keto),
            "openfga" => Ok(Self::OpenFga),
            _ => Err(ConfigError::InvalidConfig(format!(
                "invalid permissions backend: {s}; expected 'keto' or 'openfga'"
            ))),
        }
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

        let permissions_backend = std::env::var("PERMISSIONS_BACKEND")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(default_permissions_backend);

        match permissions_backend {
            PermissionsBackend::Keto => {
                #[cfg(not(feature = "keto"))]
                return Err(ConfigError::InvalidConfig(
                    "PERMISSIONS_BACKEND=keto requires the keto feature".to_string(),
                ));
            }
            PermissionsBackend::OpenFga => {
                #[cfg(not(feature = "openfga"))]
                return Err(ConfigError::InvalidConfig(
                    "PERMISSIONS_BACKEND=openfga requires the openfga feature".to_string(),
                ));
            }
        }

        let keto_read_url =
            std::env::var("KETO_READ_URL").unwrap_or_else(|_| "http://127.0.0.1:4466".to_string());
        let keto_write_url =
            std::env::var("KETO_WRITE_URL").unwrap_or_else(|_| "http://127.0.0.1:4467".to_string());
        let openfga_url =
            std::env::var("OPENFGA_URL").unwrap_or_else(|_| "http://127.0.0.1:8081".to_string());

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
            kratos_default_schema_id: std::env::var("KRATOS_DEFAULT_SCHEMA_ID")
                .unwrap_or_else(|_| "default".to_string()),
            permissions_backend,
            keto_read_url,
            keto_write_url,
            openfga_url,
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
            nats_url: std::env::var("NATS_URL").ok(),
            agent_act_token_ttl_seconds: std::env::var("AGENT_ACT_TOKEN_TTL_SECONDS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(3600),
            agent_cache_ttl_seconds: std::env::var("AGENT_CACHE_TTL_SECONDS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(5),
            public_rate_limit_requests: std::env::var("PUBLIC_RATE_LIMIT_REQUESTS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100),
            public_rate_limit_window_seconds: std::env::var("PUBLIC_RATE_LIMIT_WINDOW_SECONDS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(60),
            self_service_paths: SelfServicePaths::from_env()?,
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
        clear_env("KRATOS_DEFAULT_SCHEMA_ID");
        clear_env("KETO_READ_URL");
        clear_env("KETO_WRITE_URL");
        clear_env("OPENFGA_URL");
        clear_env("PERMISSIONS_BACKEND");
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
        clear_env("NATS_URL");
        clear_env("AGENT_ACT_TOKEN_TTL_SECONDS");
        clear_env("AGENT_CACHE_TTL_SECONDS");
        clear_env("PUBLIC_RATE_LIMIT_REQUESTS");
        clear_env("PUBLIC_RATE_LIMIT_WINDOW_SECONDS");
        clear_env("UI_PUBLIC_URL");
        for var in SELF_SERVICE_PATH_VARS {
            clear_env(var);
        }
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
        assert_eq!(config.kratos_default_schema_id, "default");
        #[cfg(feature = "openfga")]
        assert!(matches!(
            config.permissions_backend,
            PermissionsBackend::OpenFga
        ));
        #[cfg(all(not(feature = "openfga"), feature = "keto"))]
        assert!(matches!(
            config.permissions_backend,
            PermissionsBackend::Keto
        ));
        assert_eq!(config.keto_read_url, "http://127.0.0.1:4466");
        assert_eq!(config.keto_write_url, "http://127.0.0.1:4467");
        assert_eq!(config.openfga_url, "http://127.0.0.1:8081");
        assert_eq!(config.public_base_url, "http://127.0.0.1:8080");
        assert_eq!(config.ui_public_url, "http://127.0.0.1:8080");
        assert_eq!(config.saml_idp_entity_id, None);
        assert_eq!(config.saml_request_ttl_seconds, 900);
        assert_eq!(config.session_ttl_seconds, 86400);
        assert_eq!(config.nats_url, None);
        assert_eq!(config.agent_act_token_ttl_seconds, 3600);
        assert_eq!(config.agent_cache_ttl_seconds, 5);
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
    fn config_kratos_default_schema_id_override() {
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
        set_env("KRATOS_DEFAULT_SCHEMA_ID", "employee");

        let config = Config::from_env().expect("config should parse");
        drop(_guard);
        assert_eq!(config.kratos_default_schema_id, "employee");
    }

    #[cfg(feature = "openfga")]
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
        set_env("OPENFGA_URL", "http://openfga:8081");
        set_env("PERMISSIONS_BACKEND", "openfga");
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
        assert!(matches!(
            config.permissions_backend,
            PermissionsBackend::OpenFga
        ));
        assert_eq!(config.hydra_admin_url, "http://hydra:4445");
        assert_eq!(config.openfga_url, "http://openfga:8081");
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

    #[cfg(feature = "keto")]
    #[test]
    fn config_from_env_uses_keto_backend_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all_config_env();
        let ulid = valid_ulid();
        set_env("SYSTEM_TENANT_ULID", &ulid);
        set_env("DATABASE_URL", "postgres://u:p@localhost/db");
        set_env("ALLOWED_RETURN_TO_HOSTS", "example.com");
        set_env("COOKIE_SECURE", "true");
        set_env("PERMISSIONS_BACKEND", "keto");
        set_env(
            "STATE_COOKIE_SECRET",
            "test-secret-key-that-is-at-least-32-bytes-long",
        );

        let config = Config::from_env().expect("config should parse");
        drop(_guard);
        assert!(matches!(
            config.permissions_backend,
            PermissionsBackend::Keto
        ));
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
    fn config_agent_settings_parse_from_env() {
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
        set_env("NATS_URL", "nats://user:secret@nats:4222");
        set_env("AGENT_ACT_TOKEN_TTL_SECONDS", "900");
        set_env("AGENT_CACHE_TTL_SECONDS", "2");

        let config = Config::from_env().expect("config should parse");
        let debug = format!("{config:?}");
        drop(_guard);
        assert_eq!(
            config.nats_url,
            Some("nats://user:secret@nats:4222".to_string())
        );
        assert_eq!(config.agent_act_token_ttl_seconds, 900);
        assert_eq!(config.agent_cache_ttl_seconds, 2);
        assert!(!debug.contains("nats://user:secret"), "nats url is redacted");
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

    #[test]
    fn self_service_paths_default_to_identity_namespace() {
        let paths = SelfServicePaths::default();
        assert_eq!(paths.login, "/identity/login");
        assert_eq!(paths.registration, "/identity/registration");
        assert_eq!(paths.settings, "/identity/settings");
        assert_eq!(paths.recovery, "/identity/recovery");
        assert_eq!(paths.verification, "/identity/verification");
        assert_eq!(paths.logout, "/identity/logout");
        assert_eq!(paths.errors, "/identity/errors");
        assert_eq!(paths.oidc_callback, "/identity/oidc/callback");
        assert_eq!(paths.webauthn_js, "/identity/webauthn.js");
        paths.validate().expect("defaults must validate");
    }

    #[test]
    fn self_service_paths_read_from_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all_config_env();
        set_env("SELF_SERVICE_LOGIN_PATH", "/signin");
        set_env("SELF_SERVICE_WEBAUTHN_JS_PATH", "/assets/passkeys.js");
        set_env("SELF_SERVICE_OIDC_CALLBACK_PATH", "/sso/callback");

        let paths = SelfServicePaths::from_env().expect("paths should parse");
        drop(_guard);
        assert_eq!(paths.login, "/signin");
        assert_eq!(paths.webauthn_js, "/assets/passkeys.js");
        assert_eq!(paths.oidc_callback, "/sso/callback");
        // Untouched knobs keep their defaults.
        assert_eq!(paths.logout, "/identity/logout");
    }

    #[test]
    fn self_service_paths_reject_malformed_paths() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all_config_env();
        for (var, value) in [
            ("SELF_SERVICE_LOGIN_PATH", "identity/login"),
            ("SELF_SERVICE_REGISTRATION_PATH", "/"),
            ("SELF_SERVICE_SETTINGS_PATH", "/identity/settings/"),
            ("SELF_SERVICE_RECOVERY_PATH", "/identity/recovery?x=1"),
            ("SELF_SERVICE_VERIFICATION_PATH", "/identity/verification#frag"),
            ("SELF_SERVICE_LOGOUT_PATH", "/oauth2/logout"),
            ("SELF_SERVICE_ERRORS_PATH", "/self-service/errors"),
            ("SELF_SERVICE_WEBAUTHN_JS_PATH", "/.well-known/webauthn.js"),
        ] {
            clear_all_config_env();
            set_env(var, value);
            let err = SelfServicePaths::from_env().unwrap_err();
            assert!(
                matches!(err, ConfigError::InvalidConfig(_)),
                "{var}={value} must be rejected"
            );
        }
        drop(_guard);
    }

    #[test]
    fn self_service_paths_reject_duplicates() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all_config_env();
        set_env("SELF_SERVICE_LOGIN_PATH", "/identity/shared");
        set_env("SELF_SERVICE_LOGOUT_PATH", "/identity/shared");

        let err = SelfServicePaths::from_env().unwrap_err();
        drop(_guard);
        assert!(
            matches!(err, ConfigError::InvalidConfig(ref s) if s.contains("must be distinct")),
            "duplicates must be rejected: {err}"
        );
    }

    #[test]
    fn self_service_paths_reject_paths_under_oidc_callback() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all_config_env();
        set_env("SELF_SERVICE_OIDC_CALLBACK_PATH", "/identity");
        set_env("SELF_SERVICE_ERRORS_PATH", "/identity/errors");

        let err = SelfServicePaths::from_env().unwrap_err();
        drop(_guard);
        assert!(
            matches!(err, ConfigError::InvalidConfig(ref s) if s.contains("OIDC_CALLBACK")),
            "nesting under the OIDC callback must be rejected: {err}"
        );
    }
}
