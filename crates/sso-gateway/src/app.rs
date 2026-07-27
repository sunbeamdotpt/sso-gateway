use std::net::SocketAddr;
use std::sync::Arc;

use crate::jwks::ReqwestJwksService;
use crate::services::permission::PermissionBackend;
#[cfg(feature = "openfga")]
use crate::services::permission::OpenFgaPermissionBackend;
use crate::upstream_oauth::ReqwestUpstreamOAuthClient;
use crate::{
    agent_tokens::{
        AgentInvalidator, AgentTokenAuthority, AgentTokenResolver, run_invalidation_subscriber,
    },
    auth::{CachedTokenIntrospector, HydraTokenIntrospector},
    config::Config,
    db::{
        AgentActTokenRepo, AgentDelegationRepo, AgentRepo, ApplicationRepo, DbPool, IdMappingRepo,
        IdentitySchemaRepo, LoginStateRepo, PermissionNamespaceRepo, PermissionTupleRepo,
        PgTokenIntrospectionCache, SamlIdentityMappingRepo, SamlIdpKeyRepo, SamlProviderRepo,
        SamlReplayCache, SamlRequestRepo, SamlSpClientRepo, ScimGroupRepo, TenantConnectionRepo,
        TenantDomainRepo, TenantMembershipRepo, TenantRepo, TransientTokenRepo,
        bootstrap_system_tenant, create_pool,
    },
    identity_provisioner::KratosIdentityProvisioner,
    middleware::{RateLimiter, audit_middleware, auth_middleware, rate_limit_middleware},
    proto::iam::v1::{
        AgentServiceExt, ApplicationServiceExt, ClientCredentialServiceExt, FederationServiceExt,
        IdentitySelfServiceExt, IdentityServiceExt, OAuth2ConsentServiceExt,
        OAuth2DeviceServiceExt, PermissionServiceExt, ScimServiceExt, TenantServiceExt,
    },
    services::{
        agent::AgentServiceImpl,
        application::ApplicationServiceImpl,
        client_credential::ClientCredentialServiceImpl,
        federation::FederationServiceImpl,
        handlers::{
            callback::{CallbackState, router as callback_router},
            oauth2::{Oauth2State, router as oauth2_router},
            saml::{SamlState, router as saml_router},
            saml_idp::{SamlIdpState, router as saml_idp_router},
            scim::{ScimState, router as scim_router},
            self_service::{SelfServiceState, router as self_service_router},
        },
        identity::IdentityServiceImpl,
        identity_self_service::IdentitySelfServiceImpl,
        oauth2_consent::OAuth2ConsentServiceImpl,
        oauth2_device::OAuth2DeviceServiceImpl,
        permission::PermissionServiceImpl,
        scim::ScimServiceImpl,
        tenant::TenantServiceImpl,
    },
    session_token::SessionTokenSigner,
};
use axum::{
    Extension, Router as AxumRouter,
    extract::DefaultBodyLimit,
    middleware::{from_fn, from_fn_with_state},
    routing::get,
};
use connectrpc::Router as ConnectRouter;
use gamlastan::crypto::SamlSigner;
use gamlastan::crypto::keys::build_idp_keys_manager;
#[cfg(feature = "openfga")]
use sso_openfga_client::OpenFgaClient;
#[cfg(feature = "keto")]
use sso_ory_client::KetoClient;
use sso_ory_client::{HydraClient, KratosClient, error::OryClientError};
use sunbeam_g2v::{
    config::NatsConfig,
    error::ServiceResult,
    health::HealthRouter,
    mq::NatsClient,
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
    build_app_with_upstream(config, pool, None).await
}

/// Build the gateway Axum application with an optional upstream OAuth client.
///
/// The optional `upstream_oauth` override is intended for integration tests that
/// need to exercise callback flows without relying on a real upstream IdP.
pub async fn build_app_with_upstream(
    config: &Config,
    pool: DbPool,
    upstream_oauth: Option<Arc<dyn crate::upstream_oauth::UpstreamOAuthClient>>,
) -> ServiceResult<axum::Router> {
    bootstrap_system_tenant(&pool, &config.system_tenant_ulid)
        .await
        .map_err(|e| sunbeam_g2v::error::ServiceError::Database(e.to_string()))?;

    let hydra = Arc::new(
        HydraClient::new(&config.hydra_admin_url, &config.hydra_public_url)
            .map_err(|e| sunbeam_g2v::error::ServiceError::Configuration(e.to_string()))?,
    );

    let mappings = IdMappingRepo::new(pool.clone());
    let application_repo = ApplicationRepo::new(pool.clone());

    if let (Some(client_id), Some(client_secret)) = (
        config.system_bootstrap_client_id.as_deref(),
        config.system_bootstrap_client_secret.as_deref(),
    ) {
        bootstrap_system_client(
            hydra.as_ref(),
            &mappings,
            &application_repo,
            &config.system_tenant_ulid,
            client_id,
            client_secret,
        )
        .await?;
    }
    let kratos = Arc::new(
        KratosClient::new_with_public(&config.kratos_admin_url, &config.kratos_public_url)
            .map_err(|e| sunbeam_g2v::error::ServiceError::Configuration(e.to_string()))?,
    );

    let namespaces: Arc<dyn crate::services::permission::NamespaceMappingRepo> =
        Arc::new(PermissionNamespaceRepo::new(pool.clone()));
    let backend: Arc<dyn PermissionBackend> = match config.permissions_backend {
        #[cfg(feature = "keto")]
        crate::config::PermissionsBackend::Keto => Arc::new(
            KetoClient::new(&config.keto_read_url, &config.keto_write_url)
                .map_err(|e| sunbeam_g2v::error::ServiceError::Configuration(e.to_string()))?,
        ),
        #[cfg(not(feature = "keto"))]
        crate::config::PermissionsBackend::Keto => {
            return Err(sunbeam_g2v::error::ServiceError::Configuration(
                "keto backend selected but keto feature not compiled".to_string(),
            ));
        }
        #[cfg(feature = "openfga")]
        crate::config::PermissionsBackend::OpenFga => {
            let client = OpenFgaClient::new(&config.openfga_url)
                .map_err(|e| sunbeam_g2v::error::ServiceError::Configuration(e.to_string()))?;
            Arc::new(OpenFgaPermissionBackend::new(client, namespaces.clone()))
        }
        #[cfg(not(feature = "openfga"))]
        crate::config::PermissionsBackend::OpenFga => {
            return Err(sunbeam_g2v::error::ServiceError::Configuration(
                "openfga backend selected but openfga feature not compiled".to_string(),
            ));
        }
    };

    let mappings = IdMappingRepo::new(pool.clone());
    let schemas = IdentitySchemaRepo::new(pool.clone());
    let tuples = PermissionTupleRepo::new(pool.clone());
    let providers = SamlProviderRepo::new(pool.clone());
    let requests = SamlRequestRepo::new(pool.clone());
    let federation_mappings = SamlIdentityMappingRepo::new(pool.clone());
    let idp_keys = match config.saml_idp_key_encryption_key.as_ref() {
        Some(key) => SamlIdpKeyRepo::with_encryption_key(pool.clone(), key.clone()),
        None => SamlIdpKeyRepo::new(pool.clone()),
    };
    let sp_clients = SamlSpClientRepo::new(pool.clone());
    let scim_groups = ScimGroupRepo::new(pool.clone());
    let tenant_repo = TenantRepo::new(pool.clone());
    let application_store: Arc<dyn crate::db::ApplicationStore> =
        Arc::new(application_repo.clone());
    let connections = TenantConnectionRepo::new(pool.clone());
    let domains = TenantDomainRepo::new(pool.clone());
    let login_state = LoginStateRepo::new(pool.clone());
    let transient = TransientTokenRepo::new(pool.clone());
    let memberships = TenantMembershipRepo::new(pool.clone());
    let agents: Arc<dyn crate::db::AgentStore> = Arc::new(AgentRepo::new(pool.clone()));
    let agent_delegations: Arc<dyn crate::db::AgentDelegationStore> =
        Arc::new(AgentDelegationRepo::new(pool.clone()));
    let agent_act_tokens: Arc<dyn crate::db::AgentActTokenStore> =
        Arc::new(AgentActTokenRepo::new(pool.clone()));

    // Keep trait-object handles for the public callback handlers; the concrete
    // repos are moved into FederationServiceImpl below.
    let callback_connections: Arc<dyn crate::db::TenantConnectionStore> =
        Arc::new(connections.clone());
    let callback_login_state: Arc<dyn crate::db::LoginStateStore> = Arc::new(login_state.clone());
    let callback_mappings: Arc<dyn crate::db::IdMappingStore> = Arc::new(mappings.clone());
    let callback_schemas: Arc<dyn crate::db::IdentitySchemaStore> = Arc::new(schemas.clone());
    let callback_identity_provisioner: Arc<dyn crate::identity_provisioner::IdentityProvisioner> =
        Arc::new(KratosIdentityProvisioner::new(
            kratos.clone(),
            callback_mappings,
            callback_schemas,
            memberships.clone(),
            config.kratos_default_schema_id.clone(),
        ));
    let upstream_oauth: Arc<dyn crate::upstream_oauth::UpstreamOAuthClient> = upstream_oauth
        .unwrap_or_else(|| {
            Arc::new(ReqwestUpstreamOAuthClient::new(
                ReqwestUpstreamOAuthClient::default_client(),
            ))
        });
    let jwks_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let jwks_service: Arc<dyn crate::jwks::JwksService> =
        Arc::new(ReqwestJwksService::new(jwks_client));
    let session_signer = SessionTokenSigner::new(
        &config.state_cookie_secret,
        config.session_ttl_seconds as i64,
        config.public_base_url.clone(),
    );
    let session_store: Arc<dyn crate::db::SessionStore> =
        Arc::new(crate::db::PgSessionStore::new(pool.clone()));
    let replay_cache = Arc::new(SamlReplayCache::new(pool.clone()));

    let token_cache = Arc::new(PgTokenIntrospectionCache::new(pool));
    let hydra_introspector: Arc<dyn crate::auth::TokenIntrospector> =
        Arc::new(HydraTokenIntrospector::new(hydra.clone()));
    let introspector: Arc<dyn crate::auth::TokenIntrospector> =
        Arc::new(CachedTokenIntrospector::new(
            hydra_introspector,
            token_cache,
            time::Duration::seconds(config.token_introspection_cache_ttl_seconds as i64),
        ));

    let idp_entity_id = resolve_idp_entity_id(
        config.saml_idp_entity_id.clone(),
        config.public_base_url.clone(),
    );

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
        config.system_tenant_ulid.clone(),
    ));
    let application_service = Arc::new(ApplicationServiceImpl::new(
        hydra.clone(),
        mappings.clone(),
        application_repo,
        config.system_tenant_ulid.clone(),
    ));
    let client_credential_service = Arc::new(ClientCredentialServiceImpl::new(
        hydra.clone(),
        mappings.clone(),
    ));
    let identity_service = Arc::new(IdentityServiceImpl::new(
        kratos.clone(),
        mappings.clone(),
        schemas.clone(),
        memberships.clone(),
        transient.clone(),
        config.ui_public_url.clone(),
        config.kratos_default_schema_id.clone(),
    ));
    let permission_service = Arc::new(PermissionServiceImpl::new(
        backend.clone(),
        tuples,
        mappings.clone(),
        namespaces,
    ));
    let scim_service = Arc::new(ScimServiceImpl::new(
        kratos.clone(),
        backend,
        mappings.clone(),
        schemas.clone(),
        scim_groups,
    ));
    let oauth_mappings = mappings.clone();
    let consent_enabled = !config.hydra_admin_url.is_empty();
    let self_service = Arc::new(IdentitySelfServiceImpl::new(
        kratos.clone(),
        hydra.clone(),
        transient.clone(),
        mappings.clone(),
        schemas.clone(),
        memberships.clone(),
        consent_enabled,
        config.kratos_public_url.clone(),
        config.hydra_public_url.clone(),
        config.public_base_url.clone(),
        config.kratos_default_schema_id.clone(),
        config.self_service_paths.clone(),
    ));
    let oauth2_consent_service = Arc::new(OAuth2ConsentServiceImpl::new(
        hydra.clone(),
        kratos.clone(),
        transient.clone(),
        mappings.clone(),
        config.force_email_claim_client_ids.clone(),
    ));
    let oauth2_device_service = Arc::new(OAuth2DeviceServiceImpl::new(
        hydra.clone(),
        mappings.clone(),
        transient.clone(),
    ));

    // Cross-replica act-token cache invalidation rides core NATS pub/sub.
    // NATS is optional: without it the token authority degrades to
    // single-instance revocation semantics, so a failed connect is a warning,
    // not a startup error.
    let nats = match config.nats_url.as_deref() {
        Some(url) => match NatsClient::connect(&NatsConfig {
            url: url.to_string(),
            jetstream: false,
            ..Default::default()
        })
        .await
        {
            Ok(client) => Some(client),
            Err(err) => {
                tracing::warn!(%err, "NATS_URL is set but the connection failed; agent cache invalidation will be local-only");
                None
            }
        },
        None => None,
    };
    let agent_authority = Arc::new(AgentTokenAuthority::new(
        agent_act_tokens,
        agent_delegations.clone(),
        agents.clone(),
        AgentInvalidator::new(nats.clone()),
        std::time::Duration::from_secs(config.agent_cache_ttl_seconds),
        time::Duration::seconds(config.agent_act_token_ttl_seconds as i64),
    ));
    if let Some(nats) = nats {
        tokio::spawn(run_invalidation_subscriber(nats, agent_authority.clone()));
    }
    let agent_resolver: Arc<dyn AgentTokenResolver> = agent_authority.clone();

    let agent_service = Arc::new(AgentServiceImpl::new(
        hydra.clone(),
        Arc::new(mappings.clone()),
        agents,
        agent_delegations,
        Arc::new(memberships.clone()),
        agent_authority,
    ));

    let federation_service = Arc::new(FederationServiceImpl::new(
        kratos.clone(),
        providers,
        requests,
        mappings.clone(),
        federation_mappings,
        schemas,
        idp_keys.clone(),
        connections,
        domains,
        login_state,
        config.hydra_public_url.clone(),
        config.public_base_url.clone(),
        saml_signer,
        sp_certificate_pem,
        std::time::Duration::from_secs(config.saml_request_ttl_seconds),
        config.saml_require_signed_assertions,
        config.saml_require_signed_responses,
        replay_cache,
        memberships.clone(),
        config.kratos_default_schema_id.clone(),
    ));

    let oauth_state = Arc::new(
        Oauth2State::new(
            hydra.clone(),
            oauth_mappings,
            config.public_base_url.clone(),
        )
        .with_system_tenant_id(config.system_tenant_ulid.clone())
        .with_dynamic_client_registration_enabled(config.dynamic_client_registration_enabled)
        .with_kratos(kratos.clone())
        .with_force_email_claim_client_ids(config.force_email_claim_client_ids.clone())
        .with_matrix_email_claim_enabled(config.matrix_email_claim_enabled)
        .with_matrix_offline_access_enabled(config.matrix_offline_access_enabled),
    );
    let self_service_state = Arc::new(SelfServiceState::new(
        config.kratos_public_url.clone(),
        config.public_base_url.clone(),
        config.self_service_paths.clone(),
    ));
    let scim_state = Arc::new(ScimState::new(scim_service.clone()));
    let saml_state = Arc::new(SamlState::new(federation_service.clone()));
    let saml_idp_state = Arc::new(
        SamlIdpState::new(kratos.clone(), idp_keys, sp_clients, idp_entity_id)
            .with_sso_endpoint_url(format!(
                "{}/saml/sso",
                config.public_base_url.trim_end_matches('/')
            )),
    );
    let callback_state = Arc::new(
        CallbackState::new(
            callback_login_state,
            callback_connections,
            upstream_oauth,
            callback_identity_provisioner,
            jwks_service,
            session_signer.clone(),
            session_store.clone(),
            config.allowed_return_to_hosts.clone(),
            config.public_base_url.clone(),
            config.cookie_secure,
            config.cookie_samesite.clone(),
            config.session_ttl_seconds,
        )
        .with_saml(federation_service.clone()),
    );

    let connect_router: ConnectRouter = tenant_service.register(ConnectRouter::new());
    let connect_router: ConnectRouter = application_service.register(connect_router);
    let connect_router: ConnectRouter = client_credential_service.register(connect_router);
    let connect_router: ConnectRouter = agent_service.register(connect_router);
    let connect_router: ConnectRouter = identity_service.register(connect_router);
    let connect_router: ConnectRouter = permission_service.register(connect_router);
    let connect_router: ConnectRouter = scim_service.register(connect_router);
    let connect_router: ConnectRouter = federation_service.register(connect_router);
    let connect_router: ConnectRouter = self_service.register(connect_router);
    let connect_router: ConnectRouter = oauth2_consent_service.register(connect_router);
    let connect_router: ConnectRouter = oauth2_device_service.register(connect_router);
    let service_router = ServiceRouter::from_router(connect_router);

    let rate_limiter = Arc::new(RateLimiter::new(
        config.public_rate_limit_requests,
        std::time::Duration::from_secs(config.public_rate_limit_window_seconds),
    ));

    let public_routes = AxumRouter::new()
        .route("/", get(root_handler))
        .merge(oauth2_router(oauth_state))
        .merge(self_service_router(self_service_state))
        .merge(scim_router(scim_state))
        .merge(saml_router(saml_state))
        .merge(saml_idp_router(saml_idp_state))
        .merge(callback_router(callback_state))
        .layer(DefaultBodyLimit::max(1_048_576))
        .layer(from_fn_with_state(rate_limiter, rate_limit_middleware));

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
        // Audit must be outermost so that authentication failures are captured.
        .layer(from_fn(audit_middleware))
        .layer(from_fn(auth_middleware))
        .layer(Extension(introspector))
        .layer(Extension(agent_resolver))
        .layer(Extension(Arc::new(config.self_service_paths.clone())))
        .layer(Extension(session_signer))
        .layer(Extension(session_store))
        .layer(Extension(application_store))
        .layer(Extension(
            Arc::new(mappings) as Arc<dyn crate::db::IdMappingStore>
        ));

    Ok(app)
}

/// OAuth2 scopes assigned to the system bootstrap client. The bootstrap token
/// receives full administrative access to every gateway service so it can
/// provision tenants, identities, applications, SCIM resources, and permission
/// tuples without requiring a second client.
const BOOTSTRAP_CLIENT_SCOPE: &str = "tenant:read tenant:admin identity:read identity:admin application:read application:admin \
     scim:read scim:admin permission:read permission:admin agent:read agent:admin";

async fn bootstrap_system_client(
    hydra: &HydraClient,
    mappings: &IdMappingRepo,
    applications: &ApplicationRepo,
    system_tenant_ulid: &str,
    client_id: &str,
    client_secret: &str,
) -> ServiceResult<()> {
    let payload = serde_json::json!({
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_types": ["client_credentials"],
        "token_endpoint_auth_method": "client_secret_basic",
        "scope": BOOTSTRAP_CLIENT_SCOPE,
    });

    let mapping_exists = match mappings.get_tenant_id_by_ory_id("hydra", client_id).await {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(e) => {
            return Err(sunbeam_g2v::error::ServiceError::Database(e.to_string()));
        }
    };

    if mapping_exists {
        // The mapping exists; make sure the upstream Hydra client carries
        // the scopes required for bootstrapping.
        match hydra.get_oauth2_client(client_id).await {
            Ok(existing) => {
                let existing_scope = existing["scope"].as_str().unwrap_or("");
                if existing_scope != BOOTSTRAP_CLIENT_SCOPE {
                    info!("updating system bootstrap OAuth2 client scopes");
                    let mut updated = existing;
                    updated["scope"] =
                        serde_json::Value::String(BOOTSTRAP_CLIENT_SCOPE.to_string());
                    hydra
                        .update_oauth2_client(client_id, updated)
                        .await
                        .map_err(|e| {
                            sunbeam_g2v::error::ServiceError::Configuration(format!(
                                "bootstrap client update: {e}"
                            ))
                        })?;
                } else {
                    info!("system bootstrap OAuth2 client already configured");
                }
            }
            Err(OryClientError::Ory { status: 404, .. }) => {
                info!("bootstrap client mapping exists but Hydra client missing; recreating");
                hydra.create_oauth2_client(payload).await.map_err(|e| {
                    sunbeam_g2v::error::ServiceError::Configuration(format!(
                        "bootstrap client: {e}"
                    ))
                })?;
            }
            Err(e) => {
                return Err(sunbeam_g2v::error::ServiceError::Configuration(format!(
                    "bootstrap client lookup: {e}"
                )));
            }
        }
    } else {
        hydra.create_oauth2_client(payload).await.map_err(|e| {
            sunbeam_g2v::error::ServiceError::Configuration(format!("bootstrap client: {e}"))
        })?;
        mappings
            .create(system_tenant_ulid, "hydra", client_id, client_id)
            .await
            .map_err(|e| sunbeam_g2v::error::ServiceError::Database(e.to_string()))?;
    }

    // The bootstrap client is a first-party service credential that must be
    // able to route requests via x-tenant-id. Ensure the gateway's own
    // application row exists and is flagged cross-tenant.
    match applications.get_by_public_id(client_id).await {
        Ok(row) if row.cross_tenant => {
            info!(
                system_tenant = %system_tenant_ulid,
                client_id = %client_id,
                "system bootstrap application already cross-tenant"
            );
        }
        Ok(row) => {
            info!(
                system_tenant = %system_tenant_ulid,
                client_id = %client_id,
                "enabling cross_tenant for existing system bootstrap application"
            );
            applications
                .set_cross_tenant(&row.tenant_id, &row.public_id, true)
                .await
                .map_err(|e| {
                    sunbeam_g2v::error::ServiceError::Database(format!(
                        "bootstrap application cross_tenant update: {e}"
                    ))
                })?;
        }
        Err(crate::db::DbError::ApplicationNotFound) => {
            info!(
                system_tenant = %system_tenant_ulid,
                client_id = %client_id,
                "creating system bootstrap application with cross_tenant"
            );
            applications
                .create(system_tenant_ulid, client_id, true)
                .await
                .map_err(|e| {
                    sunbeam_g2v::error::ServiceError::Database(format!(
                        "bootstrap application create: {e}"
                    ))
                })?;
        }
        Err(e) => {
            return Err(sunbeam_g2v::error::ServiceError::Database(format!(
                "bootstrap application lookup: {e}"
            )));
        }
    }

    info!(
        system_tenant = %system_tenant_ulid,
        client_id = %client_id,
        "installed system bootstrap OAuth2 client"
    );

    Ok(())
}

/// Build and run the gateway server from a loaded configuration.
pub async fn run(config: Config) -> ServiceResult<()> {
    let pool = create_pool(&config.database_url, config.database_ssl_required)
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
    use axum::body::Body;
    use axum::extract::DefaultBodyLimit;
    use axum::http::{Request, StatusCode};
    use axum::middleware::from_fn_with_state;
    use axum::routing::post;
    use std::sync::Arc;
    use std::time::Duration;
    use tower::Service;
    use tower::ServiceExt;
    use ulid::Ulid;

    use super::*;
    use crate::middleware::RateLimiter;
    use crate::{
        config::Config,
        db::create_pool,
        test_support::postgres_url,
    };

    async fn ok_handler() -> StatusCode {
        StatusCode::OK
    }

    async fn echo_handler(body: axum::body::Bytes) -> axum::body::Bytes {
        body
    }

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
            hydra_admin_url: "http://127.0.0.1:4445".to_string(),
            hydra_public_url: "http://127.0.0.1:4444".to_string(),
            kratos_admin_url: "http://127.0.0.1:4434".to_string(),
            kratos_public_url: "http://127.0.0.1:4433".to_string(),
            kratos_default_schema_id: "default".to_string(),
            permissions_backend: crate::config::default_permissions_backend(),
            keto_read_url: "http://127.0.0.1:4466".to_string(),
            keto_write_url: "http://127.0.0.1:4467".to_string(),
            openfga_url: "http://127.0.0.1:8081".to_string(),
            public_base_url: "http://127.0.0.1:8080".to_string(),
            ui_public_url: "http://ui.example.com".to_string(),
            saml_sp_private_key_pem_path: None,
            saml_sp_certificate_pem_path: None,
            saml_idp_entity_id: None,
            saml_request_ttl_seconds: 900,
            saml_require_signed_assertions: true,
            saml_require_signed_responses: false,
            registration_enabled: false,
            dynamic_client_registration_enabled: true,
            matrix_email_claim_enabled: true,
            matrix_offline_access_enabled: true,
            allowed_return_to_hosts: vec!["example.com".to_string()],
            force_email_claim_client_ids: Vec::new(),
            system_bootstrap_client_id: None,
            system_bootstrap_client_secret: None,
            state_cookie_secret: "test-secret-key-for-cookies-at-least-32-bytes-long".into(),
            cookie_secure: true,
            cookie_samesite: "Lax".to_string(),
            saml_idp_key_encryption_key: None,
            tenant_connection_encryption_key: None,
            database_ssl_required: false,
            database_max_connections: 5,
            database_acquire_timeout_seconds: 5,
            database_idle_timeout_seconds: 60,
            database_max_lifetime_seconds: 300,
            database_statement_timeout_seconds: 5,
            token_introspection_cache_ttl_seconds: 30,
            session_ttl_seconds: 86400,
            nats_url: None,
            agent_act_token_ttl_seconds: 3600,
            agent_cache_ttl_seconds: 5,
            public_rate_limit_requests: 100,
            public_rate_limit_window_seconds: 60,
            self_service_paths: crate::config::SelfServicePaths::default(),
        }
    }

    #[test]
    fn bootstrap_client_scope_includes_all_service_admins() {
        let scopes: std::collections::HashSet<_> =
            BOOTSTRAP_CLIENT_SCOPE.split_whitespace().collect();
        for scope in [
            "tenant:read",
            "tenant:admin",
            "identity:read",
            "identity:admin",
            "application:read",
            "application:admin",
            "scim:read",
            "scim:admin",
            "permission:read",
            "permission:admin",
            "agent:read",
            "agent:admin",
        ] {
            assert!(scopes.contains(scope), "missing bootstrap scope {scope}");
        }
    }

    #[tokio::test]
    async fn root_handler_returns_gateway_name() {
        assert_eq!(root_handler().await, "sso-gateway");
    }

    #[test]
    fn resolve_idp_entity_id_uses_configured_value() {
        assert_eq!(
            resolve_idp_entity_id(
                Some("https://idp.example.com".into()),
                "https://gateway.example.com".into()
            ),
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
        let url = db_url_with_name(
            base,
            &format!("app_{}", Ulid::new().to_string().to_lowercase()),
        );
        let pool = create_pool(&url, false).await.unwrap();
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
    async fn callback_routes_are_public_and_wired() {
        let base = postgres_url().await;
        let url = db_url_with_name(
            base,
            &format!("app_callbacks_{}", Ulid::new().to_string().to_lowercase()),
        );
        let pool = create_pool(&url, false).await.unwrap();
        let config = test_config(url, Ulid::new().to_string());
        let app = build_app(&config, pool).await.unwrap();

        let response = app
            .clone()
            .oneshot(
                Request::get("/callbacks/oidc?code=c&state=s")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Missing/expired state returns a 400; the important part is that the
        // bearer-token middleware did not block the public callback route.
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response = app
            .oneshot(
                Request::post("/saml/acs")
                    .header(
                        axum::http::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn build_app_with_custom_idp_entity_id() {
        let base = postgres_url().await;
        let url = db_url_with_name(
            base,
            &format!("app_idp_{}", Ulid::new().to_string().to_lowercase()),
        );
        let pool = create_pool(&url, false).await.unwrap();
        let mut config = test_config(url, Ulid::new().to_string());
        config.saml_idp_entity_id = Some("https://idp.example.com".to_string());
        let app = build_app(&config, pool).await.unwrap();
        let _routes = app.into_make_service();
    }

    #[tokio::test]
    async fn build_app_loads_saml_signer_when_key_and_cert_configured() {
        let base = postgres_url().await;
        let url = db_url_with_name(
            base,
            &format!("app_key_{}", Ulid::new().to_string().to_lowercase()),
        );
        let pool = create_pool(&url, false).await.unwrap();
        let mut config = test_config(url, Ulid::new().to_string());
        config.saml_sp_private_key_pem_path = Some("tests/fixtures/saml-test-key.pem".into());
        config.saml_sp_certificate_pem_path = Some("tests/fixtures/saml-test-cert.pem".into());
        let app = build_app(&config, pool).await.unwrap();
        let _routes = app.into_make_service();
    }

    #[tokio::test]
    async fn build_app_loads_saml_signer_when_only_key_path_configured() {
        let base = postgres_url().await;
        let url = db_url_with_name(
            base,
            &format!("app_key_only_{}", Ulid::new().to_string().to_lowercase()),
        );
        let pool = create_pool(&url, false).await.unwrap();
        let mut config = test_config(url, Ulid::new().to_string());
        config.saml_sp_private_key_pem_path = Some("tests/fixtures/saml-test-key.pem".into());
        let app = build_app(&config, pool).await.unwrap();
        let _routes = app.into_make_service();
    }

    #[tokio::test]
    async fn build_app_returns_error_when_saml_key_file_missing() {
        let base = postgres_url().await;
        let url = db_url_with_name(
            base,
            &format!("app_missing_key_{}", Ulid::new().to_string().to_lowercase()),
        );
        let pool = create_pool(&url, false).await.unwrap();
        let mut config = test_config(url, Ulid::new().to_string());
        config.saml_sp_private_key_pem_path = Some("tests/fixtures/does-not-exist.pem".into());
        assert!(build_app(&config, pool).await.is_err());
    }

    #[tokio::test]
    async fn run_returns_error_for_unbindable_address() {
        let base = postgres_url().await;
        let url = db_url_with_name(
            base,
            &format!("app_run_{}", Ulid::new().to_string().to_lowercase()),
        );
        let mut config = test_config(url, Ulid::new().to_string());
        config.bind_addr = "192.0.2.1:80".parse().unwrap();
        let result = run(config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn build_app_returns_error_for_invalid_hydra_url() {
        let base = postgres_url().await;
        let url = db_url_with_name(
            base,
            &format!("app_hydra_url_{}", Ulid::new().to_string().to_lowercase()),
        );
        let pool = create_pool(&url, false).await.unwrap();
        let mut config = test_config(url, Ulid::new().to_string());
        config.hydra_admin_url = "not a valid url".to_string();
        assert!(build_app(&config, pool).await.is_err());
    }

    #[tokio::test]
    async fn build_app_returns_error_for_invalid_kratos_url() {
        let base = postgres_url().await;
        let url = db_url_with_name(
            base,
            &format!("app_kratos_url_{}", Ulid::new().to_string().to_lowercase()),
        );
        let pool = create_pool(&url, false).await.unwrap();
        let mut config = test_config(url, Ulid::new().to_string());
        config.kratos_admin_url = "not a valid url".to_string();
        assert!(build_app(&config, pool).await.is_err());
    }

    #[cfg(feature = "openfga")]
    #[tokio::test]
    async fn build_app_returns_error_for_invalid_openfga_url() {
        let base = postgres_url().await;
        let url = db_url_with_name(
            base,
            &format!("app_openfga_url_{}", Ulid::new().to_string().to_lowercase()),
        );
        let pool = create_pool(&url, false).await.unwrap();
        let mut config = test_config(url, Ulid::new().to_string());
        config.openfga_url = "not a valid url".to_string();
        assert!(build_app(&config, pool).await.is_err());
    }

    #[cfg(feature = "keto")]
    #[tokio::test]
    async fn build_app_returns_error_for_invalid_keto_url() {
        let base = postgres_url().await;
        let url = db_url_with_name(
            base,
            &format!("app_keto_url_{}", Ulid::new().to_string().to_lowercase()),
        );
        let pool = create_pool(&url, false).await.unwrap();
        let mut config = test_config(url, Ulid::new().to_string());
        config.permissions_backend = crate::config::PermissionsBackend::Keto;
        config.keto_read_url = "not a valid url".to_string();
        assert!(build_app(&config, pool).await.is_err());
    }

    #[tokio::test]
    async fn build_app_returns_error_for_invalid_saml_certificate_file() {
        let base = postgres_url().await;
        let url = db_url_with_name(
            base,
            &format!("app_cert_{}", Ulid::new().to_string().to_lowercase()),
        );
        let pool = create_pool(&url, false).await.unwrap();
        let mut config = test_config(url, Ulid::new().to_string());
        config.saml_sp_private_key_pem_path = Some("tests/fixtures/saml-test-key.pem".into());
        config.saml_sp_certificate_pem_path = Some("tests/fixtures/does-not-exist.pem".into());
        assert!(build_app(&config, pool).await.is_err());
    }

    #[tokio::test]
    async fn public_routes_apply_body_size_limit() {
        let app = AxumRouter::new()
            .route("/", post(echo_handler))
            .layer(DefaultBodyLimit::max(1_048_576));

        let oversized = vec![b'x'; 1_048_577];
        let response = app
            .oneshot(Request::post("/").body(Body::from(oversized)).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn public_routes_apply_rate_limit() {
        let limiter = Arc::new(RateLimiter::new(2, Duration::from_secs(60)));
        let mut app = AxumRouter::new()
            .route("/", get(ok_handler))
            .layer(from_fn_with_state(limiter, rate_limit_middleware));

        for i in 0..2 {
            let response = app
                .call(Request::get("/").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "request {} should be allowed",
                i
            );
        }

        let response = app
            .call(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    // -----------------------------------------------------------------------
    // Bootstrap client cross-tenant provisioning regression tests
    // -----------------------------------------------------------------------

    /// Starts a minimal Hydra admin stub for bootstrap_system_client tests.
    /// The GET /admin/clients/{id} endpoint always returns 404 (so the client
    /// is created), and POST /admin/clients echoes a minimal client document.
    async fn start_bootstrap_hydra_stub() -> (tokio::task::JoinHandle<()>, String) {
        let app = axum::Router::new()
            .route(
                "/admin/clients/{id}",
                axum::routing::get(|| async { axum::http::StatusCode::NOT_FOUND }),
            )
            .route(
                "/admin/clients",
                axum::routing::post(|axum::Json(body): axum::Json<serde_json::Value>| async move {
                    let client_id = body
                        .get("client_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("bootstrap-client")
                        .to_string();
                    axum::Json(serde_json::json!({ "client_id": client_id }))
                }),
            );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (handle, format!("http://{addr}"))
    }

    async fn bootstrap_test_pool(db_name: &str) -> (DbPool, String) {
        let base = postgres_url().await;
        let url = db_url_with_name(base, db_name);
        let pool = create_pool(&url, false).await.unwrap();
        let system_tenant_ulid = Ulid::new().to_string();
        bootstrap_system_tenant(&pool, &system_tenant_ulid).await.unwrap();
        (pool, system_tenant_ulid)
    }

    #[tokio::test]
    async fn bootstrap_system_client_creates_cross_tenant_application_row() {
        let (pool, system_tenant_ulid) =
            bootstrap_test_pool(&format!("bs_create_{}", Ulid::new().to_string().to_lowercase())).await;

        let mappings = IdMappingRepo::new(pool.clone());
        let applications = ApplicationRepo::new(pool.clone());
        let (_handle, hydra_url) = start_bootstrap_hydra_stub().await;
        let hydra = HydraClient::new(&hydra_url, "http://ignored").unwrap();

        bootstrap_system_client(
            &hydra,
            &mappings,
            &applications,
            &system_tenant_ulid,
            "bootstrap-client",
            "bootstrap-secret",
        )
        .await
        .unwrap();

        let mapping = mappings
            .get_tenant_id_by_ory_id("hydra", "bootstrap-client")
            .await
            .unwrap();
        assert_eq!(mapping, Some(system_tenant_ulid.clone()));

        let app = applications.get_by_public_id("bootstrap-client").await.unwrap();
        assert_eq!(app.tenant_id, system_tenant_ulid);
        assert!(app.cross_tenant, "bootstrap application must be cross-tenant");
    }

    #[tokio::test]
    async fn bootstrap_system_client_upgrades_existing_application_to_cross_tenant() {
        let (pool, system_tenant_ulid) =
            bootstrap_test_pool(&format!("bs_upgrade_{}", Ulid::new().to_string().to_lowercase())).await;

        let mappings = IdMappingRepo::new(pool.clone());
        let applications = ApplicationRepo::new(pool.clone());

        // Pre-create an application row without cross_tenant, as would happen
        // if the bootstrap client was provisioned before this release.
        mappings
            .create(&system_tenant_ulid, "hydra", "bootstrap-client", "bootstrap-client")
            .await
            .unwrap();
        let existing = applications
            .create(&system_tenant_ulid, "bootstrap-client", false)
            .await
            .unwrap();
        assert!(!existing.cross_tenant);

        let (_handle, hydra_url) = start_bootstrap_hydra_stub().await;
        let hydra = HydraClient::new(&hydra_url, "http://ignored").unwrap();

        bootstrap_system_client(
            &hydra,
            &mappings,
            &applications,
            &system_tenant_ulid,
            "bootstrap-client",
            "bootstrap-secret",
        )
        .await
        .unwrap();

        let app = applications.get_by_public_id("bootstrap-client").await.unwrap();
        assert!(app.cross_tenant, "bootstrap application must be upgraded to cross-tenant");
    }
}
