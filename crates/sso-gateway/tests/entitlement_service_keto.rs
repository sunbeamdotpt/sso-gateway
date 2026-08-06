// SSO-027: tests may unwrap/expect freely; the panic/default bans target production code.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)
)]

//! Entitlement service integration tests against a real Ory Keto container.
//!
//! Group-derived entitlements rely on Keto subject sets: the seeded
//! application link tuple points at `entitlements:<group>#member`, which the
//! keto backend writes as a real `subject_set` that checks traverse.

#![cfg(feature = "keto")]

use std::sync::Arc;

use sso_gateway::db::{ApplicationRow, ApplicationStore, DbError};
use sso_gateway::services::entitlement::{
    EntitlementLevel, EntitlementService, EntitlementServiceImpl, GATEWAY_APP_OBJECT,
};
use sso_gateway::services::permission::PermissionBackend;
use sso_ory_client::KetoClient;
use testcontainers::{ContainerAsync, GenericImage};

mod support;

/// One Keto container per test binary, shared by all tests: the support
/// harness removes every testcontainers-labelled container on first start,
/// so concurrently-started containers can be killed mid-test. Tests stay
/// isolated through per-test tenant ids (objects are tenant-prefixed).
static KETO: tokio::sync::OnceCell<(ContainerAsync<GenericImage>, String, String)> =
    tokio::sync::OnceCell::const_new();

async fn keto_urls() -> (String, String) {
    let (_, read_url, write_url) = KETO
        .get_or_init(|| async { support::start_keto().await.expect("keto should start") })
        .await;
    (read_url.clone(), write_url.clone())
}

async fn entitlement_service() -> (EntitlementServiceImpl, String) {
    let (read_url, write_url) = keto_urls().await;
    let backend: Arc<dyn PermissionBackend> =
        Arc::new(KetoClient::new(&read_url, &write_url).expect("keto client should build"));
    let service = EntitlementServiceImpl::new(backend, Arc::new(StubApplicationStore));
    let tenant_id = ulid::Ulid::new().to_string();
    (service, tenant_id)
}

/// Application store stub; entitlement checks never read it.
#[derive(Debug)]
struct StubApplicationStore;

#[async_trait::async_trait]
impl ApplicationStore for StubApplicationStore {
    async fn create(
        &self,
        _tenant_id: &str,
        _public_id: &str,
        _cross_tenant: bool,
        _registration_source: &str,
    ) -> Result<ApplicationRow, DbError> {
        Err(DbError::ApplicationNotFound)
    }

    async fn get(&self, _tenant_id: &str, _public_id: &str) -> Result<ApplicationRow, DbError> {
        Err(DbError::ApplicationNotFound)
    }

    async fn get_by_public_id(&self, _public_id: &str) -> Result<ApplicationRow, DbError> {
        Err(DbError::ApplicationNotFound)
    }

    async fn list_by_tenant(&self, _tenant_id: &str) -> Result<Vec<ApplicationRow>, DbError> {
        Ok(Vec::new())
    }

    async fn set_cross_tenant(
        &self,
        _tenant_id: &str,
        _public_id: &str,
        _cross_tenant: bool,
    ) -> Result<ApplicationRow, DbError> {
        Err(DbError::ApplicationNotFound)
    }

    async fn delete(&self, _tenant_id: &str, _public_id: &str) -> Result<(), DbError> {
        Ok(())
    }
}

/// Serializes the tests in this binary: the shared Keto container runs on an
/// in-memory store that answers concurrent tuple writes with "Unable to
/// serialize access due to a concurrent update in another session" 400s, so
/// the tests must not write at the same time.
static KETO_WRITE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Full lifecycle on Keto: seeding, group-derived member/admin resolution
/// through subject sets, direct grants, claims, and scope ceilings.
#[tokio::test]
async fn entitlement_service_keto_lifecycle() {
    let _guard = KETO_WRITE_LOCK.lock().await;
    let (svc, tenant) = entitlement_service().await;

    svc.ensure_namespace(&tenant)
        .await
        .expect("ensure_namespace should succeed");

    // Seed the gateway application with the employees group.
    svc.seed_application(&tenant, GATEWAY_APP_OBJECT, &["employees".to_string()])
        .await
        .expect("seed_application should succeed");

    // Nobody is entitled yet.
    assert!(
        !svc.is_member(&tenant, "alice", GATEWAY_APP_OBJECT)
            .await
            .expect("check should succeed")
    );

    // Alice joins the employees group: both member and admin resolve through
    // the subject-set link (RFC 0001 "admin ⊇ group members").
    svc.set_group_membership(&tenant, "employees", "alice", true)
        .await
        .expect("set_group_membership should succeed");
    assert!(
        svc.check(&tenant, "alice", GATEWAY_APP_OBJECT, "member")
            .await
            .expect("check should succeed"),
        "group-derived member check should resolve via the subject set"
    );
    assert!(
        svc.check(&tenant, "alice", GATEWAY_APP_OBJECT, "admin")
            .await
            .expect("check should succeed"),
        "group-derived admin check should resolve via the subject set"
    );
    assert!(
        !svc.check(&tenant, "bob", GATEWAY_APP_OBJECT, "member")
            .await
            .expect("check should succeed")
    );

    // The scope ceiling follows the gateway entitlement and stays additive:
    // admins keep the OIDC baseline alongside the iam scopes (SSO-036).
    let ceiling = svc.effective_scope_ceiling(&tenant, "alice").await;
    assert!(
        ceiling.iter().any(|s| s == "tenant:admin"),
        "admin ceiling expected, got {ceiling:?}"
    );
    assert!(
        ceiling.iter().any(|s| s == "openid"),
        "admin ceiling must include the OIDC baseline, got {ceiling:?}"
    );

    // Direct grants work alongside group-derived access.
    svc.grant(&tenant, "carol", "kanban", EntitlementLevel::Member)
        .await
        .expect("grant should succeed");
    assert!(
        svc.is_member(&tenant, "carol", "kanban")
            .await
            .expect("check should succeed")
    );
    let claim = svc.mint_claim(&tenant, "carol", "kanban").await;
    assert_eq!(
        claim,
        serde_json::json!({ "entitlements": { "kanban": ["member"] } })
    );

    svc.revoke(&tenant, "carol", "kanban", EntitlementLevel::Member)
        .await
        .expect("revoke should succeed");
    assert!(
        !svc.is_member(&tenant, "carol", "kanban")
            .await
            .expect("check should succeed")
    );

    // Leaving the group removes the derived entitlement.
    svc.set_group_membership(&tenant, "employees", "alice", false)
        .await
        .expect("set_group_membership should succeed");
    assert!(
        !svc.is_member(&tenant, "alice", GATEWAY_APP_OBJECT)
            .await
            .expect("check should succeed")
    );
}

/// Bootstrap re-runs seeding on every start; every write must be idempotent.
/// Keto silently deduplicates duplicate inserts and ignores deletes of
/// missing tuples (verified against the container), so the default
/// `ensure_tuples` delegation is sufficient on this backend.
#[tokio::test]
async fn entitlement_service_keto_seed_and_membership_are_idempotent() {
    let _guard = KETO_WRITE_LOCK.lock().await;
    let (svc, tenant) = entitlement_service().await;

    for _ in 0..2 {
        svc.ensure_namespace(&tenant)
            .await
            .expect("ensure_namespace should succeed");
        svc.seed_application(&tenant, GATEWAY_APP_OBJECT, &["employees".to_string()])
            .await
            .expect("repeated seed_application should succeed");
        svc.set_group_membership(&tenant, "employees", "alice", true)
            .await
            .expect("repeated membership add should succeed");
    }

    assert!(
        svc.check(&tenant, "alice", GATEWAY_APP_OBJECT, "member")
            .await
            .expect("check should succeed")
    );
    assert!(
        svc.check(&tenant, "alice", GATEWAY_APP_OBJECT, "admin")
            .await
            .expect("check should succeed")
    );

    // Repeated removal and revoke-before-grant are not errors either.
    svc.set_group_membership(&tenant, "employees", "alice", false)
        .await
        .expect("membership removal should succeed");
    svc.set_group_membership(&tenant, "employees", "alice", false)
        .await
        .expect("repeated membership removal should succeed");
    svc.revoke(
        &tenant,
        "alice",
        GATEWAY_APP_OBJECT,
        EntitlementLevel::Admin,
    )
    .await
    .expect("revoke without grant should succeed");
}

// -------------------------------------------------------------------------
// DCR legacy backfill (SSO-039 §5) at the full-app bootstrap level
// -------------------------------------------------------------------------

/// Postgres + Hydra + Keto containers for the bootstrap-level backfill test.
/// The backfill test gets its OWN Keto container: the shared one uses an
/// in-memory sqlite DSN, whose "concurrent update in another session" 400s
/// under this test's heavy tuple writes flake the lifecycle tests.
type AppContainers = (
    ContainerAsync<GenericImage>,
    ContainerAsync<GenericImage>,
    ContainerAsync<GenericImage>,
    String,
    String,
    String,
    String,
    String,
);

static APP_CONTAINERS: tokio::sync::OnceCell<AppContainers> = tokio::sync::OnceCell::const_new();

/// (database_url, hydra_admin_url, hydra_public_url, keto_read_url, keto_write_url)
async fn app_container_urls() -> (String, String, String, String, String) {
    let (_, _, _, database_url, hydra_admin_url, hydra_public_url, keto_read_url, keto_write_url) =
        APP_CONTAINERS
            .get_or_init(|| async {
                let (pg, database_url) = support::start_postgres()
                    .await
                    .expect("postgres should start");
                let (hydra, hydra_admin_url, hydra_public_url) =
                    support::start_hydra().await.expect("hydra should start");
                let (keto, keto_read_url, keto_write_url) =
                    support::start_keto().await.expect("keto should start");
                (
                    pg,
                    hydra,
                    keto,
                    database_url,
                    hydra_admin_url,
                    hydra_public_url,
                    keto_read_url,
                    keto_write_url,
                )
            })
            .await;
    (
        database_url.clone(),
        hydra_admin_url.clone(),
        hydra_public_url.clone(),
        keto_read_url.clone(),
        keto_write_url.clone(),
    )
}

/// Gateway config pointing at this binary's containers, with the system
/// bootstrap client enabled so `build_app` runs the full production startup
/// path (Hydra provisioning + entitlement seed + DCR backfill).
fn gateway_config(
    database_url: &str,
    hydra_admin_url: &str,
    hydra_public_url: &str,
    keto_read_url: &str,
    keto_write_url: &str,
    system_tenant_ulid: &str,
) -> sso_gateway::config::Config {
    sso_gateway::config::Config {
        bind_addr: "127.0.0.1:0".parse().expect("addr"),
        system_tenant_ulid: system_tenant_ulid.to_string(),
        database_url: database_url.to_string(),
        hydra_admin_url: hydra_admin_url.to_string(),
        hydra_public_url: hydra_public_url.to_string(),
        kratos_admin_url: "http://127.0.0.1:1".to_string(),
        kratos_public_url: "http://127.0.0.1:1".to_string(),
        kratos_default_schema_id: "default".to_string(),
        permissions_backend: sso_gateway::config::PermissionsBackend::Keto,
        keto_read_url: keto_read_url.to_string(),
        keto_write_url: keto_write_url.to_string(),
        openfga_url: "http://127.0.0.1:1".to_string(),
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
    }
}

/// SSO-039 §5: a restart backfills pre-enforcement DCR clients (Hydra
/// mapping, no `applications` row, no tuples) with the default group links
/// plus their DCR-marked row, and never reseeds clients that already carry
/// tuples — deliberate revocations survive restarts. Keto twin of the
/// OpenFGA test in `entitlement_service_openfga.rs`.
#[tokio::test]
async fn dcr_legacy_backfill_is_restart_safe() {
    let _guard = KETO_WRITE_LOCK.lock().await;
    let (database_url, hydra_admin_url, hydra_public_url, keto_read_url, keto_write_url) =
        app_container_urls().await;
    let tenant = ulid::Ulid::new().to_string();
    let config = gateway_config(
        &database_url,
        &hydra_admin_url,
        &hydra_public_url,
        &keto_read_url,
        &keto_write_url,
        &tenant,
    );

    // First boot: system tenant, bootstrap client, gateway entitlement seed.
    let pool = sso_gateway::db::create_pool(&database_url, false)
        .await
        .expect("database pool should be created");
    let _app = sso_gateway::app::build_app(&config, pool)
        .await
        .expect("first boot should succeed");

    // Fabricate the exact legacy shape: a hydra mapping with no applications
    // row and no tuples (what the DCR handler wrote before entitlement
    // enforcement).
    let pool = sso_gateway::db::create_pool(&database_url, false)
        .await
        .expect("database pool should be created");
    let mappings = sso_gateway::db::PgIdMappingStore::new(pool.clone());
    let legacy_public = ulid::Ulid::new().to_string();
    sso_gateway::db::IdMappingStore::create(
        &mappings,
        &tenant,
        "hydra",
        &legacy_public,
        &format!("ory-{legacy_public}"),
    )
    .await
    .expect("legacy mapping should be created");
    // The manually-patched prod shape: tuples granted out-of-band, still no
    // applications row.
    let patched_public = ulid::Ulid::new().to_string();
    sso_gateway::db::IdMappingStore::create(
        &mappings,
        &tenant,
        "hydra",
        &patched_public,
        &format!("ory-{patched_public}"),
    )
    .await
    .expect("patched mapping should be created");
    let backend: Arc<dyn PermissionBackend> = Arc::new(
        KetoClient::new(&keto_read_url, &keto_write_url).expect("keto client should build"),
    );
    let service = EntitlementServiceImpl::new(
        backend,
        Arc::new(sso_gateway::db::ApplicationRepo::new(pool.clone())),
    );
    service
        .grant(&tenant, "carol", &patched_public, EntitlementLevel::Member)
        .await
        .expect("out-of-band patch grant should succeed");

    // Restart: the startup backfill converges both clients.
    let restart_pool = sso_gateway::db::create_pool(&database_url, false)
        .await
        .expect("database pool should be created");
    let _app = sso_gateway::app::build_app(&config, restart_pool)
        .await
        .expect("restart boot should succeed");

    // The legacy client got its DCR row and the employees group-link seed.
    let applications = sso_gateway::db::ApplicationRepo::new(pool.clone());
    let legacy_row =
        sso_gateway::db::ApplicationStore::get_by_public_id(&applications, &legacy_public)
            .await
            .expect("legacy client should have an applications row");
    assert_eq!(legacy_row.registration_source, "dcr");
    assert_eq!(legacy_row.tenant_id, tenant);
    assert!(
        service
            .has_any_tuples(&tenant, &legacy_public)
            .await
            .expect("tuple read should succeed"),
        "the backfill must seed tuple-less legacy clients"
    );
    service
        .set_group_membership(&tenant, "employees", "alice", true)
        .await
        .expect("group membership should succeed");
    assert!(
        service
            .is_member(&tenant, "alice", &legacy_public)
            .await
            .expect("check should succeed"),
        "the backfill seed resolves through the keto subject set"
    );

    // The patched client got its row but was NOT reseeded: carol keeps her
    // grant, while employees members gain nothing.
    let patched_row =
        sso_gateway::db::ApplicationStore::get_by_public_id(&applications, &patched_public)
            .await
            .expect("patched client should have an applications row");
    assert_eq!(patched_row.registration_source, "dcr");
    assert!(
        service
            .is_member(&tenant, "carol", &patched_public)
            .await
            .expect("check should succeed"),
        "the out-of-band grant must survive the backfill"
    );
    assert!(
        !service
            .is_member(&tenant, "alice", &patched_public)
            .await
            .expect("check should succeed"),
        "a tuple-having client must never be reseeded"
    );

    // A second restart is a no-op: rows stay singular, tuples are unchanged.
    let second_restart_pool = sso_gateway::db::create_pool(&database_url, false)
        .await
        .expect("database pool should be created");
    let _app = sso_gateway::app::build_app(&config, second_restart_pool)
        .await
        .expect("second restart boot should succeed");
    for public_id in [&legacy_public, &patched_public] {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM applications WHERE public_id = $1")
                .bind(public_id)
                .fetch_one(&pool)
                .await
                .expect("row count should query");
        assert_eq!(count, 1, "no duplicate applications rows for {public_id}");
    }
    assert!(
        service
            .is_member(&tenant, "carol", &patched_public)
            .await
            .expect("check should succeed")
    );
    assert!(
        !service
            .is_member(&tenant, "alice", &patched_public)
            .await
            .expect("check should succeed"),
        "restarts must not resurrect the group link on the patched client"
    );
}
