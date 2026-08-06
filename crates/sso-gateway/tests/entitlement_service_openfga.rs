// SSO-027: tests may unwrap/expect freely; the panic/default bans target production code.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)
)]

//! Entitlement service integration tests against a real OpenFGA container and
//! a real Postgres namespace registry.
//!
//! Covers the SSO-029/SSO-030 production crashes: fresh bootstrap, restart
//! idempotency, coexistence with flat-model namespaces, upgrade from the old
//! broken entitlement model, and adoption of orphaned stores.

#![cfg(feature = "openfga")]

use std::sync::Arc;

use serde_json::json;
use sso_gateway::db::{ApplicationRepo, PgPermissionNamespaceStore, create_pool};
use sso_gateway::services::entitlement::{
    ENTITLEMENT_NAMESPACE, EntitlementLevel, EntitlementService, EntitlementServiceImpl,
    GATEWAY_APP_OBJECT,
};
use sso_gateway::services::permission::{
    NamespaceMappingRepo, OpenFgaPermissionBackend, PermissionBackend,
};
use sso_openfga_client::OpenFgaClient;
use testcontainers::{ContainerAsync, GenericImage};

mod support;

/// One Postgres and one OpenFGA container per test binary, shared by all
/// tests: the support harness removes every testcontainers-labelled container
/// on first start, so concurrently-started containers can be killed mid-test.
/// Tests stay isolated through per-test tenant ids (per-tenant stores and
/// registry rows).
static CONTAINERS: tokio::sync::OnceCell<(
    ContainerAsync<GenericImage>,
    ContainerAsync<GenericImage>,
    String,
    String,
)> = tokio::sync::OnceCell::const_new();

async fn container_urls() -> (String, String) {
    let (_, _, database_url, openfga_url) = CONTAINERS
        .get_or_init(|| async {
            let (pg, database_url) = support::start_postgres()
                .await
                .expect("postgres should start");
            let (openfga, openfga_url) = support::start_openfga()
                .await
                .expect("openfga should start");
            (pg, openfga, database_url, openfga_url)
        })
        .await;
    (database_url.clone(), openfga_url.clone())
}

struct Stack {
    tenant: String,
    pool: sqlx::PgPool,
    client: OpenFgaClient,
    namespaces: Arc<PgPermissionNamespaceStore>,
    applications: ApplicationRepo,
    service: EntitlementServiceImpl,
}

async fn start_stack() -> Stack {
    let (database_url, openfga_url) = container_urls().await;

    let pool = create_pool(&database_url, false)
        .await
        .expect("database pool should be created");
    // A plain tenant row with a unique slug; the shared database cannot run
    // the system-tenant bootstrap more than once (slug is globally unique).
    let tenant = ulid::Ulid::new().to_string();
    sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
        .bind(&tenant)
        .bind(format!("t-{}", tenant.to_lowercase()))
        .bind("Test Tenant")
        .execute(&pool)
        .await
        .expect("tenant should be created");

    let client = OpenFgaClient::new(&openfga_url).expect("openfga client should build");
    let namespaces = Arc::new(PgPermissionNamespaceStore::new(pool.clone()));
    let backend: Arc<dyn PermissionBackend> = Arc::new(OpenFgaPermissionBackend::new(
        client.clone(),
        namespaces.clone(),
    ));
    let applications = ApplicationRepo::new(pool.clone());
    let service = EntitlementServiceImpl::new(backend, Arc::new(applications.clone()));

    Stack {
        tenant,
        pool,
        client,
        namespaces,
        applications,
        service,
    }
}

impl Stack {
    async fn entitlement_record(&self) -> sso_gateway::services::permission::NamespaceRecord {
        NamespaceMappingRepo::get(
            self.namespaces.as_ref(),
            &self.tenant,
            ENTITLEMENT_NAMESPACE,
        )
        .await
        .expect("namespace lookup should succeed")
        .expect("entitlement namespace should be registered")
    }
}

/// The broken model shipped before the fix: tuple writes referenced the
/// `entitlements` object type, which this model never defined (SSO-029), and
/// its bare types collided with every flat-model namespace (SSO-030).
fn old_broken_model() -> serde_json::Value {
    json!({
        "schema_version": "1.1",
        "type_definitions": [
            {"type": "user"},
            {
                "type": "group",
                "relations": { "member": { "this": {} } },
                "metadata": {
                    "relations": {
                        "member": { "directly_related_user_types": [{ "type": "user" }] }
                    }
                }
            },
            {
                "type": "application",
                "relations": {
                    "group": { "this": {} },
                    "member": {
                        "union": {
                            "child": [
                                { "this": {} },
                                {
                                    "tuple_to_userset": {
                                        "tupleset": { "relation": "group" },
                                        "computed_userset": { "relation": "member" }
                                    }
                                }
                            ]
                        }
                    },
                    "admin": {
                        "union": {
                            "child": [
                                { "this": {} },
                                {
                                    "tuple_to_userset": {
                                        "tupleset": { "relation": "group" },
                                        "computed_userset": { "relation": "member" }
                                    }
                                }
                            ]
                        }
                    }
                },
                "metadata": {
                    "relations": {
                        "group": { "directly_related_user_types": [{ "type": "group" }] },
                        "member": { "directly_related_user_types": [{ "type": "user" }] },
                        "admin": { "directly_related_user_types": [{ "type": "user" }] }
                    }
                }
            }
        ]
    })
}

/// Full lifecycle on a fresh OpenFGA — this is the exact bootstrap sequence
/// that crashed on an empty deployment (SSO-029 regression).
#[tokio::test]
async fn entitlement_service_openfga_lifecycle() {
    let stack = start_stack().await;
    let svc = &stack.service;
    let tenant = &stack.tenant;

    // The bootstrap sequence from app.rs: ensure + seed the gateway app.
    svc.ensure_namespace(tenant)
        .await
        .expect("ensure_namespace should succeed on a fresh OpenFGA (SSO-029)");
    svc.seed_application(tenant, GATEWAY_APP_OBJECT, &["employees".to_string()])
        .await
        .expect("seed_application should succeed on a fresh OpenFGA (SSO-029)");

    // Nobody is entitled yet.
    assert!(
        !svc.is_member(tenant, "alice", GATEWAY_APP_OBJECT)
            .await
            .expect("check should succeed")
    );

    // Alice joins employees: member AND admin resolve through the userset
    // link (RFC 0001 "admin ⊇ group members").
    svc.set_group_membership(tenant, "employees", "alice", true)
        .await
        .expect("set_group_membership should succeed");
    assert!(
        svc.check(tenant, "alice", GATEWAY_APP_OBJECT, "member")
            .await
            .expect("check should succeed"),
        "group-derived member check should resolve"
    );
    assert!(
        svc.check(tenant, "alice", GATEWAY_APP_OBJECT, "admin")
            .await
            .expect("check should succeed"),
        "group-derived admin check should resolve"
    );
    assert!(
        !svc.check(tenant, "bob", GATEWAY_APP_OBJECT, "member")
            .await
            .expect("check should succeed")
    );

    // The scope ceiling follows the gateway entitlement and stays additive:
    // admins keep the OIDC baseline alongside the iam scopes (SSO-036).
    let ceiling = svc.effective_scope_ceiling(tenant, "alice").await;
    assert!(
        ceiling.iter().any(|s| s == "tenant:admin"),
        "admin ceiling expected, got {ceiling:?}"
    );
    assert!(
        ceiling.iter().any(|s| s == "openid"),
        "admin ceiling must include the OIDC baseline, got {ceiling:?}"
    );
    let claim = svc.mint_claim(tenant, "alice", GATEWAY_APP_OBJECT).await;
    let levels = claim["entitlements"][GATEWAY_APP_OBJECT]
        .as_array()
        .expect("claim should list levels");
    assert!(levels.iter().any(|l| l == "member"));
    assert!(levels.iter().any(|l| l == "admin"));

    // Direct grants work alongside group-derived access. Application rows
    // reference an id_mappings entry, as when the app is registered with its
    // Hydra client.
    sso_gateway::db::IdMappingRepo::new(stack.pool.clone())
        .create(tenant, "hydra", "kanban", "kanban-hydra-client")
        .await
        .expect("id mapping should be created");
    stack
        .applications
        .create(
            tenant,
            "kanban",
            false,
            sso_gateway::db::REGISTRATION_SOURCE_ADMIN,
        )
        .await
        .expect("application row should be created");
    svc.grant(tenant, "carol", "kanban", EntitlementLevel::Member)
        .await
        .expect("grant should succeed");
    assert!(
        svc.is_member(tenant, "carol", "kanban")
            .await
            .expect("check should succeed")
    );
    assert_eq!(
        svc.mint_claim(tenant, "carol", "kanban").await,
        json!({ "entitlements": { "kanban": ["member"] } })
    );

    svc.revoke(tenant, "carol", "kanban", EntitlementLevel::Member)
        .await
        .expect("revoke should succeed");
    assert!(
        !svc.is_member(tenant, "carol", "kanban")
            .await
            .expect("check should succeed")
    );

    // Disabling a user removes all explicit entitlements.
    svc.grant(tenant, "dave", "kanban", EntitlementLevel::Admin)
        .await
        .expect("grant should succeed");
    svc.remove_all_for_identity(tenant, "dave")
        .await
        .expect("remove_all_for_identity should succeed");
    assert!(
        !svc.check(tenant, "dave", "kanban", "admin")
            .await
            .expect("check should succeed")
    );

    // Leaving the group removes the derived entitlement.
    svc.set_group_membership(tenant, "employees", "alice", false)
        .await
        .expect("set_group_membership should succeed");
    assert!(
        !svc.is_member(tenant, "alice", GATEWAY_APP_OBJECT)
            .await
            .expect("check should succeed")
    );
}

/// Bootstrap re-runs seeding on every start; previously that 400ed on the
/// duplicate tuple and crashlooped the gateway.
#[tokio::test]
async fn entitlement_service_openfga_restart_is_idempotent() {
    let stack = start_stack().await;
    let svc = &stack.service;
    let tenant = &stack.tenant;

    for _ in 0..2 {
        svc.ensure_namespace(tenant)
            .await
            .expect("repeated ensure_namespace should succeed");
        svc.seed_application(tenant, GATEWAY_APP_OBJECT, &["employees".to_string()])
            .await
            .expect("repeated seed_application should succeed (no duplicate tuple error)");
        svc.set_group_membership(tenant, "employees", "alice", true)
            .await
            .expect("repeated membership add should succeed");
    }

    assert!(
        svc.check(tenant, "alice", GATEWAY_APP_OBJECT, "member")
            .await
            .expect("check should succeed")
    );
    assert!(
        svc.check(tenant, "alice", GATEWAY_APP_OBJECT, "admin")
            .await
            .expect("check should succeed")
    );

    // Repeated removals and revoke-before-grant are not errors either.
    svc.set_group_membership(tenant, "employees", "alice", false)
        .await
        .expect("membership removal should succeed");
    svc.set_group_membership(tenant, "employees", "alice", false)
        .await
        .expect("repeated membership removal should succeed");
    svc.revoke(tenant, "alice", GATEWAY_APP_OBJECT, EntitlementLevel::Admin)
        .await
        .expect("revoke without grant should succeed");
}

/// SSO-030 regression: a flat-model namespace (every flat model declares a
/// bare `user` type) must not block the entitlement namespace.
#[tokio::test]
async fn entitlement_service_openfga_coexists_with_flat_namespace() {
    let stack = start_stack().await;
    let tenant = &stack.tenant;

    // SCIM registers its flat group namespace first, exactly like production.
    let backend = OpenFgaPermissionBackend::new(stack.client.clone(), stack.namespaces.clone());
    backend
        .ensure_namespace(tenant, "scim_group", &["member".to_string()])
        .await
        .expect("flat namespace should be ensured");

    // This used to fail with "namespace type conflict: type user is already
    // registered" (SSO-030).
    stack
        .service
        .ensure_namespace(tenant)
        .await
        .expect("entitlement namespace must coexist with a flat-model namespace (SSO-030)");
    stack
        .service
        .seed_application(tenant, GATEWAY_APP_OBJECT, &["employees".to_string()])
        .await
        .expect("seed should succeed");

    // Both namespaces keep working: the entitlement store is distinct from
    // the scim_group store.
    let entitlement_record = stack.entitlement_record().await;
    let scim_record = stack
        .namespaces
        .get(tenant, "scim_group")
        .await
        .expect("lookup should succeed")
        .expect("scim_group namespace should be registered");
    assert_ne!(entitlement_record.store_id, scim_record.store_id);
    assert_eq!(
        entitlement_record.types,
        vec![ENTITLEMENT_NAMESPACE.to_string()]
    );

    stack
        .service
        .set_group_membership(tenant, "employees", "alice", true)
        .await
        .expect("membership should succeed");
    assert!(
        stack
            .service
            .check(tenant, "alice", GATEWAY_APP_OBJECT, "admin")
            .await
            .expect("check should succeed")
    );
}

/// Upgrade path: a deployment that already ran the broken model has a store
/// plus a registry row describing it. The fixed `ensure_model` must publish
/// the corrected model into the SAME store — never re-initialize tuples —
/// and converge the type index.
#[tokio::test]
async fn entitlement_service_openfga_upgrade_from_broken_model() {
    let stack = start_stack().await;
    let tenant = &stack.tenant;

    // Recreate the pre-fix persisted state: store + old model + registry row.
    let store_id = stack
        .client
        .create_store(&format!("{tenant}-{ENTITLEMENT_NAMESPACE}"))
        .await
        .expect("store should be created");
    let old_model = old_broken_model();
    let old_model_id = stack
        .client
        .write_model(&store_id, &old_model)
        .await
        .expect("old model should be written");
    NamespaceMappingRepo::upsert(
        stack.namespaces.as_ref(),
        tenant,
        &sso_gateway::services::permission::NamespaceRecord {
            namespace: ENTITLEMENT_NAMESPACE.to_string(),
            model: old_model,
            types: vec![],
            store_id: Some(store_id.clone()),
            model_id: Some(old_model_id.clone()),
            created_at: None,
            updated_at: None,
        },
    )
    .await
    .expect("old registry row should be written");

    // The fixed bootstrap converges in place.
    stack
        .service
        .ensure_namespace(tenant)
        .await
        .expect("fixed ensure_model should converge the existing store");
    let record = stack.entitlement_record().await;
    assert_eq!(
        record.store_id.as_deref(),
        Some(store_id.as_str()),
        "the existing store must be reused, never re-created"
    );
    assert_ne!(
        record.model_id.as_deref(),
        Some(old_model_id.as_str()),
        "a new model version must be published"
    );
    // The type index converged: stale bare/old types are gone.
    assert_eq!(record.types, vec![ENTITLEMENT_NAMESPACE.to_string()]);

    // Seeding and group-derived checks work on the converged store.
    stack
        .service
        .seed_application(tenant, GATEWAY_APP_OBJECT, &["employees".to_string()])
        .await
        .expect("seed should succeed after upgrade");
    stack
        .service
        .set_group_membership(tenant, "employees", "alice", true)
        .await
        .expect("membership should succeed");
    assert!(
        stack
            .service
            .check(tenant, "alice", GATEWAY_APP_OBJECT, "member")
            .await
            .expect("check should succeed")
    );
    assert!(
        stack
            .service
            .check(tenant, "alice", GATEWAY_APP_OBJECT, "admin")
            .await
            .expect("check should succeed")
    );
}

/// The SSO-030 crash left orphaned stores behind (created before the failing
/// registry upsert). A fixed boot must adopt the orphan instead of piling up
/// new ones.
#[tokio::test]
async fn entitlement_service_openfga_adopts_orphan_store() {
    let stack = start_stack().await;
    let tenant = &stack.tenant;

    // Crash debris: an empty store with the conventional name and no
    // registry row.
    let orphan_id = stack
        .client
        .create_store(&format!("{tenant}-{ENTITLEMENT_NAMESPACE}"))
        .await
        .expect("orphan store should be created");

    stack
        .service
        .ensure_namespace(tenant)
        .await
        .expect("ensure_model should adopt the orphan store");

    let record = stack.entitlement_record().await;
    assert_eq!(
        record.store_id.as_deref(),
        Some(orphan_id.as_str()),
        "the orphan store must be adopted, not replaced"
    );
    assert!(
        record.model_id.as_deref().is_some_and(|id| !id.is_empty()),
        "the corrected model must be published into the adopted store"
    );

    // Still exactly one store with that name.
    let stores = stack
        .client
        .list_stores()
        .await
        .expect("stores should list");
    let named = stores["stores"]
        .as_array()
        .expect("stores array")
        .iter()
        .filter(|s| s["name"] == format!("{tenant}-{ENTITLEMENT_NAMESPACE}"))
        .count();
    assert_eq!(named, 1, "no duplicate store may be created");

    // The adopted store is fully usable.
    stack
        .service
        .seed_application(tenant, GATEWAY_APP_OBJECT, &["employees".to_string()])
        .await
        .expect("seed should succeed on the adopted store");
    stack
        .service
        .set_group_membership(tenant, "employees", "alice", true)
        .await
        .expect("membership should succeed");
    assert!(
        stack
            .service
            .check(tenant, "alice", GATEWAY_APP_OBJECT, "admin")
            .await
            .expect("check should succeed")
    );
}

/// Full-app bootstrap E2E: `build_app` with the system bootstrap client runs
/// the exact production startup path (Hydra client provisioning + entitlement
/// namespace ensure + gateway app seed). This is the sequence that crashed
/// fresh deployments (SSO-029) and crashlooped restarts. Building twice
/// proves both.
#[tokio::test]
async fn app_bootstrap_with_entitlements_is_restart_safe() {
    let (database_url, openfga_url) = container_urls().await;
    let (_hydra, hydra_admin_url, hydra_public_url) = support::start_hydra()
        .await
        .expect("hydra should start");

    let system_tenant_ulid = ulid::Ulid::new().to_string();
    let config = sso_gateway::config::Config {
        bind_addr: "127.0.0.1:0".parse().expect("addr"),
        system_tenant_ulid,
        database_url: database_url.clone(),
        hydra_admin_url,
        hydra_public_url,
        kratos_admin_url: "http://127.0.0.1:1".to_string(),
        kratos_public_url: "http://127.0.0.1:1".to_string(),
        kratos_default_schema_id: "default".to_string(),
        permissions_backend: sso_gateway::config::PermissionsBackend::OpenFga,
        keto_read_url: "http://127.0.0.1:1".to_string(),
        keto_write_url: "http://127.0.0.1:1".to_string(),
        openfga_url,
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
        default_entitlement_groups: vec!["employees".to_string()],
        dcr_unused_registration_ttl_days: 7,
        dcr_gc_enabled: true,
        system_bootstrap_client_id: Some("system-bootstrap".to_string()),
        system_bootstrap_client_secret: Some("system-bootstrap-secret".to_string()),
        state_cookie_secret: "test-secret-key-for-cookies-at-least-32-bytes-long".into(),
        cookie_secure: true,
        cookie_samesite: "Lax".to_string(),
        saml_idp_key_encryption_key: None,
        tenant_connection_encryption_key: None,
        database_ssl_required: false,
        database_max_connections: 5,
        database_acquire_timeout_seconds: 30,
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
        self_service_paths: sso_gateway::config::SelfServicePaths::default(),
    };

    // First boot: provisions the Hydra client, creates the entitlement store,
    // publishes the model, and seeds the gateway application.
    let pool = create_pool(&database_url, false)
        .await
        .expect("database pool should be created");
    let _app = sso_gateway::app::build_app(&config, pool)
        .await
        .expect("first bootstrap should succeed (SSO-029 regression)");

    // Restart: every step must converge instead of erroring on the state the
    // first boot left behind.
    let pool = create_pool(&database_url, false)
        .await
        .expect("database pool should be created");
    let _app = sso_gateway::app::build_app(&config, pool)
        .await
        .expect("restart bootstrap should succeed (no duplicate tuple crash)");
}
