use std::net::SocketAddr;
use std::sync::Arc;

use crate::{
    config::Config,
    db::{
        AuditLogRepo, DbPool, IdMappingRepo, IdentitySchemaRepo, PermissionTupleRepo,
        SamlIdentityMappingRepo, SamlIdpKeyRepo, SamlProviderRepo, SamlReplayCache,
        SamlRequestRepo, SamlSpClientRepo, ScimGroupRepo, TenantApiKeyRepo, TenantRepo,
        bootstrap_system_tenant, create_pool,
    },
    middleware::{audit_middleware, auth_middleware},
    oauth2::{Oauth2State, router as oauth2_router},
    proto::iam::v1::{
        ApplicationServiceExt, FederationServiceExt, IdentitySelfServiceExt, IdentityServiceExt,
        OAuth2ConsentServiceExt, PermissionServiceExt, ScimServiceExt, TenantServiceExt,
    },
    saml::{SamlState, router as saml_router},
    saml_idp::{SamlIdpState, router as saml_idp_router},
    scim::{ScimState, router as scim_router},
    services::{
        application::ApplicationServiceImpl, federation::FederationServiceImpl,
        identity::IdentityServiceImpl, identity_self_service::IdentitySelfServiceImpl,
        oauth2_consent::OAuth2ConsentServiceImpl, permission::PermissionServiceImpl,
        scim::ScimServiceImpl, tenant::TenantServiceImpl,
    },
};
use axum::{Extension, Router as AxumRouter, middleware::from_fn, routing::get};
use connectrpc::Router as ConnectRouter;
use gamlastan::crypto::SamlSigner;
use gamlastan::crypto::keys::build_idp_keys_manager;
use sso_ory_client::{HydraClient, KetoClient, KratosClient};
use sunbeam_g2v::{
    error::ServiceResult,
    health::HealthRouter,
    router::ServiceRouter,
    server::{ServerConfig, builder::ServerBuilder},
};
use tracing::info;

async fn root_handler() -> &'static str {
    "sso-gateway"
}

fn resolve_idp_entity_id(idp_entity_id: Option<String>, public_base_url: String) -> String {
    idp_entity_id.unwrap_or(public_base_url)
}

fn build_server_config(addr: SocketAddr, name: &str) -> ServerConfig {
    ServerConfig {
        addr,
        name: name.to_string(),
        ..ServerConfig::default()
    }
}

/// Build the gateway Axum application from a loaded configuration and pool.
///
/// This is split out of `run` so unit tests can exercise the wiring without
/// actually binding a TCP socket or serving requests.
pub async fn build_app(config: &Config, pool: DbPool) -> ServiceResult<axum::Router> {
    bootstrap_system_tenant(&pool, &config.system_tenant_ulid)
        .await
        .map_err(|e| sunbeam_g2v::error::ServiceError::Database(e.to_string()))?;

    let hydra = Arc::new(
        HydraClient::new(&config.hydra_admin_url, &config.hydra_public_url)
            .map_err(|e| sunbeam_g2v::error::ServiceError::Configuration(e.to_string()))?,
    );
    let kratos = Arc::new(
        KratosClient::new_with_public(&config.kratos_admin_url, &config.kratos_public_url)
            .map_err(|e| sunbeam_g2v::error::ServiceError::Configuration(e.to_string()))?,
    );
    let keto = Arc::new(
        KetoClient::new(&config.keto_read_url, &config.keto_write_url)
            .map_err(|e| sunbeam_g2v::error::ServiceError::Configuration(e.to_string()))?,
    );

    let mappings = IdMappingRepo::new(pool.clone());
    let schemas = IdentitySchemaRepo::new(pool.clone());
    let tuples = PermissionTupleRepo::new(pool.clone());
    let providers = SamlProviderRepo::new(pool.clone());
    let requests = SamlRequestRepo::new(pool.clone());
    let federation_mappings = SamlIdentityMappingRepo::new(pool.clone());
    let idp_keys = SamlIdpKeyRepo::new(pool.clone());
    let sp_clients = SamlSpClientRepo::new(pool.clone());
    let scim_groups = ScimGroupRepo::new(pool.clone());
    let tenant_repo = TenantRepo::new(pool.clone());
    let api_keys = TenantApiKeyRepo::new(pool.clone());
    let audit_log = AuditLogRepo::new(pool.clone());
    let replay_cache = Arc::new(SamlReplayCache::new(pool));

    let idp_entity_id = resolve_idp_entity_id(config.saml_idp_entity_id.clone(), config.public_base_url.clone());

    let (saml_signer, sp_certificate_pem) =
        if let Some(key_path) = &config.saml_sp_private_key_pem_path {
            let pem = tokio::fs::read(key_path).await.map_err(|e| {
                sunbeam_g2v::error::ServiceError::Configuration(format!("saml key: {e}"))
            })?;
            let mut key_manager = build_idp_keys_manager(&pem).map_err(|e| {
                sunbeam_g2v::error::ServiceError::Configuration(format!("saml key: {e}"))
            })?;
            let cert_pem = if let Some(cert_path) = &config.saml_sp_certificate_pem_path {
                let cert = tokio::fs::read_to_string(cert_path).await.map_err(|e| {
                    sunbeam_g2v::error::ServiceError::Configuration(format!("saml cert: {e}"))
                })?;
                key_manager.add_trusted_cert(cert.clone().into_bytes());
                Some(cert)
            } else {
                None
            };
            (Some(Arc::new(SamlSigner::new(key_manager))), cert_pem)
        } else {
            (None, None)
        };

    let tenant_service = Arc::new(TenantServiceImpl::new(
        tenant_repo,
        api_keys.clone(),
        config.system_tenant_ulid.clone(),
    ));
    let application_service =
        Arc::new(ApplicationServiceImpl::new(hydra.clone(), mappings.clone()));
    let identity_service = Arc::new(IdentityServiceImpl::new(
        kratos.clone(),
        mappings.clone(),
        schemas.clone(),
    ));
    let permission_service = Arc::new(PermissionServiceImpl::new(keto.clone(), tuples));
    let scim_service = Arc::new(ScimServiceImpl::new(
        kratos.clone(),
        keto,
        mappings.clone(),
        schemas.clone(),
        scim_groups,
    ));
    let oauth_mappings = mappings.clone();
    let scim_mappings = mappings.clone();
    let self_service = Arc::new(IdentitySelfServiceImpl::new(kratos.clone()));
    let oauth2_consent_service = Arc::new(OAuth2ConsentServiceImpl::new(hydra.clone()));

    let federation_service = Arc::new(FederationServiceImpl::new(
        kratos.clone(),
        providers,
        requests,
        mappings.clone(),
        federation_mappings,
        schemas,
        idp_keys.clone(),
        config.hydra_public_url.clone(),
        config.public_base_url.clone(),
        saml_signer,
        sp_certificate_pem,
        std::time::Duration::from_secs(config.saml_request_ttl_seconds),
        config.saml_require_signed_assertions,
        config.saml_require_signed_responses,
        replay_cache,
    ));

    let oauth_state = Arc::new(Oauth2State::new(
        hydra.clone(),
        oauth_mappings,
        config.public_base_url.clone(),
    ));
    let scim_state = Arc::new(ScimState::new(
        scim_service.clone(),
        hydra.clone(),
        scim_mappings,
    ));
    let saml_state = Arc::new(SamlState::new(federation_service.clone()));
    let saml_idp_state = Arc::new(SamlIdpState::new(
        kratos.clone(),
        idp_keys,
        sp_clients,
        idp_entity_id,
    ));

    let connect_router: ConnectRouter = tenant_service.register(ConnectRouter::new());
    let connect_router: ConnectRouter = application_service.register(connect_router);
    let connect_router: ConnectRouter = identity_service.register(connect_router);
    let connect_router: ConnectRouter = permission_service.register(connect_router);
    let connect_router: ConnectRouter = scim_service.register(connect_router);
    let connect_router: ConnectRouter = federation_service.register(connect_router);
    let connect_router: ConnectRouter = self_service.register(connect_router);
    let connect_router: ConnectRouter = oauth2_consent_service.register(connect_router);
    let service_router = ServiceRouter::from_router(connect_router);

    let public_routes = AxumRouter::new()
        .route("/", get(root_handler))
        .merge(oauth2_router(oauth_state))
        .merge(scim_router(scim_state))
        .merge(saml_router(saml_state))
        .merge(saml_idp_router(saml_idp_state));

    let health = HealthRouter::new();

    let server_config = build_server_config(config.bind_addr, "sso-gateway");

    let server = ServerBuilder::new()
        .with_router(service_router)
        .with_config(server_config)
        .with_health(health)
        .with_routes(public_routes)
        .build_axum()?;

    let app = server
        .app()
        .layer(from_fn(audit_middleware))
        .layer(from_fn(auth_middleware))
        .layer(Extension(api_keys))
        .layer(Extension(audit_log))
        .layer(Extension(kratos))
        .layer(Extension(mappings));

    Ok(app)
}

/// Build and run the gateway server from a loaded configuration.
pub async fn run(config: Config) -> ServiceResult<()> {
    let pool = create_pool(&config.database_url)
        .await
        .map_err(|e| sunbeam_g2v::error::ServiceError::Database(e.to_string()))?;

    let app = build_app(&config, pool).await?;

    let listener = tokio::net::TcpListener::bind(config.bind_addr)
        .await
        .map_err(|e| sunbeam_g2v::error::ServiceError::Internal(format!("bind: {e}")))?;

    info!("listening on http://{}", config.bind_addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| sunbeam_g2v::error::ServiceError::Internal(format!("axum::serve: {e}")))?;

    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
}

#[cfg(test)]
mod tests {
    use ulid::Ulid;

    use super::*;
    use crate::{config::Config, db::create_pool, test_support::postgres_url};

    fn db_url_with_name(base: &str, db_name: &str) -> String {
        if let Some(query_start) = base.rfind('?') {
            let before_query = &base[..query_start];
            let query = &base[query_start..];
            if let Some(db_sep) = before_query.rfind('/') {
                format!("{}{}{}", &before_query[..db_sep + 1], db_name, query)
            } else {
                format!("{}/{}", before_query, db_name)
            }
        } else if let Some(db_sep) = base.rfind('/') {
            format!("{}{}", &base[..db_sep + 1], db_name)
        } else {
            format!("{}/{}", base, db_name)
        }
    }

    fn test_config(database_url: String, system_tenant_ulid: String) -> Config {
        Config {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            system_tenant_ulid,
            database_url,
            redis_url: "redis://127.0.0.1:6379".to_string(),
            hydra_admin_url: "http://127.0.0.1:4445".to_string(),
            hydra_public_url: "http://127.0.0.1:4444".to_string(),
            kratos_admin_url: "http://127.0.0.1:4434".to_string(),
            kratos_public_url: "http://127.0.0.1:4433".to_string(),
            keto_read_url: "http://127.0.0.1:4466".to_string(),
            keto_write_url: "http://127.0.0.1:4467".to_string(),
            public_base_url: "http://127.0.0.1:8080".to_string(),
            saml_sp_private_key_pem_path: None,
            saml_sp_certificate_pem_path: None,
            saml_idp_entity_id: None,
            saml_request_ttl_seconds: 900,
            saml_require_signed_assertions: true,
            saml_require_signed_responses: false,
            registration_enabled: false,
            allowed_return_to_hosts: vec![],
        }
    }

    #[tokio::test]
    async fn root_handler_returns_gateway_name() {
        assert_eq!(root_handler().await, "sso-gateway");
    }

    #[test]
    fn resolve_idp_entity_id_uses_configured_value() {
        assert_eq!(
            resolve_idp_entity_id(Some("https://idp.example.com".into()), "https://gateway.example.com".into()),
            "https://idp.example.com"
        );
    }

    #[test]
    fn resolve_idp_entity_id_falls_back_to_public_base_url() {
        assert_eq!(
            resolve_idp_entity_id(None, "https://gateway.example.com".into()),
            "https://gateway.example.com"
        );
    }

    #[test]
    fn build_server_config_sets_addr_and_name() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let config = build_server_config(addr, "sso-gateway");
        assert_eq!(config.addr, addr);
        assert_eq!(config.name, "sso-gateway");
    }

    #[tokio::test]
    async fn build_app_wires_routes_and_layers() {
        let base = postgres_url().await;
        let url = db_url_with_name(base, &format!("app_{}", Ulid::new().to_string().to_lowercase()));
        let pool = create_pool(&url).await.unwrap();
        let system_tenant_ulid = Ulid::new().to_string();
        let config = test_config(url, system_tenant_ulid.clone());
        let app = build_app(&config, pool.clone()).await.unwrap();
        // A simple smoke test that the returned router is usable.
        let _routes = app.into_make_service();

        // System tenant should be bootstrapped by build_app.
        let slug: String = sqlx::query_scalar("SELECT slug FROM tenants WHERE id = $1")
            .bind(&system_tenant_ulid)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(slug, "system");
    }

    #[tokio::test]
    async fn build_app_with_custom_idp_entity_id() {
        let base = postgres_url().await;
        let url = db_url_with_name(base, &format!("app_idp_{}", Ulid::new().to_string().to_lowercase()));
        let pool = create_pool(&url).await.unwrap();
        let mut config = test_config(url, Ulid::new().to_string());
        config.saml_idp_entity_id = Some("https://idp.example.com".to_string());
        let app = build_app(&config, pool).await.unwrap();
        let _routes = app.into_make_service();
    }

    #[tokio::test]
    async fn build_app_loads_saml_signer_when_key_and_cert_configured() {
        let base = postgres_url().await;
        let url = db_url_with_name(base, &format!("app_key_{}", Ulid::new().to_string().to_lowercase()));
        let pool = create_pool(&url).await.unwrap();
        let mut config = test_config(url, Ulid::new().to_string());
        config.saml_sp_private_key_pem_path = Some("tests/fixtures/saml-test-key.pem".into());
        config.saml_sp_certificate_pem_path = Some("tests/fixtures/saml-test-cert.pem".into());
        let app = build_app(&config, pool).await.unwrap();
        let _routes = app.into_make_service();
    }

    #[tokio::test]
    async fn build_app_loads_saml_signer_when_only_key_path_configured() {
        let base = postgres_url().await;
        let url = db_url_with_name(base, &format!("app_key_only_{}", Ulid::new().to_string().to_lowercase()));
        let pool = create_pool(&url).await.unwrap();
        let mut config = test_config(url, Ulid::new().to_string());
        config.saml_sp_private_key_pem_path = Some("tests/fixtures/saml-test-key.pem".into());
        let app = build_app(&config, pool).await.unwrap();
        let _routes = app.into_make_service();
    }

    #[tokio::test]
    async fn build_app_returns_error_when_saml_key_file_missing() {
        let base = postgres_url().await;
        let url = db_url_with_name(base, &format!("app_missing_key_{}", Ulid::new().to_string().to_lowercase()));
        let pool = create_pool(&url).await.unwrap();
        let mut config = test_config(url, Ulid::new().to_string());
        config.saml_sp_private_key_pem_path = Some("tests/fixtures/does-not-exist.pem".into());
        assert!(build_app(&config, pool).await.is_err());
    }

    #[tokio::test]
    async fn run_returns_error_for_unbindable_address() {
        let base = postgres_url().await;
        let url = db_url_with_name(base, &format!("app_run_{}", Ulid::new().to_string().to_lowercase()));
        let mut config = test_config(url, Ulid::new().to_string());
        config.bind_addr = "192.0.2.1:80".parse().unwrap();
        let result = run(config).await;
        assert!(result.is_err());
    }
}
