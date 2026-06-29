use std::sync::Arc;

use crate::{
    config::Config,
    db::{
        AuditLogRepo, IdMappingRepo, IdentitySchemaRepo, PermissionTupleRepo,
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

/// Build and run the gateway server from a loaded configuration.
pub async fn run(config: Config) -> ServiceResult<()> {
    let pool = create_pool(&config.database_url)
        .await
        .map_err(|e| sunbeam_g2v::error::ServiceError::Database(e.to_string()))?;

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

    let idp_entity_id = config
        .saml_idp_entity_id
        .clone()
        .unwrap_or_else(|| config.public_base_url.clone());

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

    let oauth_state = Arc::new(Oauth2State {
        hydra: hydra.clone(),
        mappings: oauth_mappings,
        public_base_url: config.public_base_url.clone(),
    });
    let scim_state = Arc::new(ScimState {
        service: scim_service.clone(),
        hydra: hydra.clone(),
        mappings: scim_mappings,
    });
    let saml_state = Arc::new(SamlState {
        service: federation_service.clone(),
    });
    let saml_idp_state = Arc::new(SamlIdpState {
        kratos: kratos.clone(),
        idp_keys,
        sp_clients,
        idp_entity_id,
    });

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
        .route("/", get(|| async { "sso-gateway" }))
        .merge(oauth2_router(oauth_state))
        .merge(scim_router(scim_state))
        .merge(saml_router(saml_state))
        .merge(saml_idp_router(saml_idp_state));

    let health = HealthRouter::new();

    let server_config = ServerConfig {
        addr: config.bind_addr,
        name: "sso-gateway".to_string(),
        ..ServerConfig::default()
    };

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

    let listener = tokio::net::TcpListener::bind(server.config().addr)
        .await
        .map_err(|e| sunbeam_g2v::error::ServiceError::Internal(format!("bind: {e}")))?;

    info!("listening on http://{}", server.config().addr);

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
