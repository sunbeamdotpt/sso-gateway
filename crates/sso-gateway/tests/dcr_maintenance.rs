// SSO-027: tests may unwrap/expect freely; the panic/default bans target production code.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)
)]

//! DCR unused-registration GC integration tests (SSO-039 §1), against real
//! Postgres + Hydra + permissions-backend containers, on both the `keto` and
//! `openfga` features.
//!
//! Both feature modules share one Postgres and one Hydra container, so each
//! test's reaper can observe (and reap) the other test's old provisional
//! registrations. Assertions are therefore state-based — "my old client is
//! gone afterwards" — never count-based, and every fabricated client that
//! must survive is protected by youth or an applications row, which every
//! reaper honors regardless of backend.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use sso_gateway::db::{
    AgentRepo, ApplicationRepo, ApplicationStore, IdMappingStore, PgIdMappingStore, TenantRepo,
    create_pool,
};
use sso_gateway::services::dcr_maintenance::DcrMaintenance;
use sso_gateway::services::entitlement::{EntitlementService, EntitlementServiceImpl};
use sso_gateway::services::handlers::oauth2::HydraOperations;
use sso_ory_client::HydraClient;
use testcontainers::{ContainerAsync, GenericImage};

mod support;

/// One Postgres and one Hydra container per test binary, shared by all
/// tests (see the file header for the cross-test interleaving contract). The
/// strings are (database_url, hydra_admin_url, hydra_public_url).
type SharedContainers = (
    ContainerAsync<GenericImage>,
    ContainerAsync<GenericImage>,
    String,
    String,
    String,
);

static SHARED: tokio::sync::OnceCell<SharedContainers> = tokio::sync::OnceCell::const_new();

/// (database_url, hydra_admin_url, hydra_public_url)
async fn shared_urls() -> (String, String, String) {
    let (_, _, database_url, hydra_admin_url, hydra_public_url) = SHARED
        .get_or_init(|| async {
            let (pg, database_url) = support::start_postgres()
                .await
                .expect("postgres should start");
            let (hydra, hydra_admin_url, hydra_public_url) =
                support::start_hydra().await.expect("hydra should start");
            (pg, hydra, database_url, hydra_admin_url, hydra_public_url)
        })
        .await;
    (
        database_url.clone(),
        hydra_admin_url.clone(),
        hydra_public_url.clone(),
    )
}

/// A fabricated DCR registration: a real Hydra client plus its mapping row.
/// Returns (public_id, ory client id).
async fn fabricate_registration(
    pool: &sqlx::PgPool,
    hydra: &HydraClient,
    tenant: &str,
    old: bool,
) -> (String, String) {
    let created = hydra
        .create_oauth2_client(json!({
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "scope": "openid profile email",
            "redirect_uris": ["https://app.example.com/callback"],
            "token_endpoint_auth_method": "none",
        }))
        .await
        .expect("hydra client should be created");
    let ory_id = created["client_id"]
        .as_str()
        .expect("client_id")
        .to_string();
    let public_id = ulid::Ulid::new().to_string();
    let mappings = PgIdMappingStore::new(pool.clone());
    IdMappingStore::create(&mappings, tenant, "hydra", &public_id, &ory_id)
        .await
        .expect("mapping should be created");
    if old {
        sqlx::query(
            "UPDATE id_mappings SET created_at = NOW() - INTERVAL '8 days' WHERE public_id = $1",
        )
        .bind(&public_id)
        .execute(pool)
        .await
        .expect("mapping should be aged");
    }
    (public_id, ory_id)
}

async fn assert_hydra_client_gone(hydra: &HydraClient, ory_id: &str) {
    let err = hydra
        .get_oauth2_client(ory_id)
        .await
        .expect_err("reaped client must be gone from Hydra");
    assert!(
        matches!(
            err,
            sso_ory_client::error::OryClientError::Ory { status: 404, .. }
        ),
        "expected a 404, got {err:?}"
    );
}

async fn run_reaper_scenario(
    pool: sqlx::PgPool,
    hydra_admin_url: &str,
    hydra_public_url: &str,
    entitlements: Arc<dyn EntitlementService>,
) {
    let tenant_id = ulid::Ulid::new().to_string();
    sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
        .bind(&tenant_id)
        .bind(format!("t-{}", tenant_id.to_lowercase()))
        .bind("Reaper Test Tenant")
        .execute(&pool)
        .await
        .expect("tenant should be created");

    let hydra = HydraClient::new(hydra_admin_url, hydra_public_url).expect("hydra client");
    let (old_public, old_ory) = fabricate_registration(&pool, &hydra, &tenant_id, true).await;
    let (young_public, young_ory) = fabricate_registration(&pool, &hydra, &tenant_id, false).await;
    let (row_public, row_ory) = fabricate_registration(&pool, &hydra, &tenant_id, true).await;
    let applications = ApplicationRepo::new(pool.clone());
    ApplicationStore::create(
        &applications,
        &tenant_id,
        &row_public,
        false,
        sso_gateway::db::REGISTRATION_SOURCE_DCR,
    )
    .await
    .expect("applications row should be created");

    let hydra_ops: Arc<dyn HydraOperations> =
        Arc::new(HydraClient::new(hydra_admin_url, hydra_public_url).expect("hydra client"));
    let maintenance = DcrMaintenance::new(
        Arc::new(PgIdMappingStore::new(pool.clone())),
        Arc::new(ApplicationRepo::new(pool.clone())),
        entitlements,
        hydra_ops,
        Arc::new(TenantRepo::new(pool.clone())),
        Arc::new(AgentRepo::new(pool.clone())),
        vec!["employees".to_string()],
        Duration::from_secs(7 * 86_400),
    );
    let stats = maintenance.reap_unused_registrations().await;
    assert_eq!(stats.errors, 0, "reaper run had errors: {stats:?}");

    // The old provisional registration is reaped; young and row-having
    // registrations survive. (Another test's reaper may have beaten this one
    // to the delete — the final state is what matters.)
    assert_hydra_client_gone(&hydra, &old_ory).await;
    let mappings = PgIdMappingStore::new(pool.clone());
    assert!(
        matches!(
            IdMappingStore::get_ory_id(&mappings, &tenant_id, "hydra", &old_public).await,
            Err(sso_gateway::db::DbError::MappingNotFound)
        ),
        "reaped mapping must be deleted"
    );

    hydra
        .get_oauth2_client(&young_ory)
        .await
        .expect("young registration must survive");
    hydra
        .get_oauth2_client(&row_ory)
        .await
        .expect("row-having registration must survive");
    assert!(
        IdMappingStore::get_ory_id(&mappings, &tenant_id, "hydra", &young_public)
            .await
            .is_ok()
    );
    assert!(
        IdMappingStore::get_ory_id(&mappings, &tenant_id, "hydra", &row_public)
            .await
            .is_ok()
    );
}

#[cfg(feature = "openfga")]
mod openfga {
    use super::*;
    use sso_gateway::db::PgPermissionNamespaceStore;
    use sso_gateway::services::permission::{OpenFgaPermissionBackend, PermissionBackend};
    use sso_openfga_client::OpenFgaClient;

    static OPENFGA: tokio::sync::OnceCell<(ContainerAsync<GenericImage>, String)> =
        tokio::sync::OnceCell::const_new();

    async fn openfga_url() -> String {
        let (_, url) = OPENFGA
            .get_or_init(|| async {
                support::start_openfga()
                    .await
                    .expect("openfga should start")
            })
            .await;
        url.clone()
    }

    #[tokio::test]
    async fn reaper_deletes_only_old_provisional_registrations() {
        let (database_url, hydra_admin_url, hydra_public_url) = shared_urls().await;
        let openfga_url = openfga_url().await;
        let pool = create_pool(&database_url, false)
            .await
            .expect("database pool should be created");
        let client = OpenFgaClient::new(&openfga_url).expect("openfga client should build");
        let backend: Arc<dyn PermissionBackend> = Arc::new(OpenFgaPermissionBackend::new(
            client,
            Arc::new(PgPermissionNamespaceStore::new(pool.clone())),
        ));
        let entitlements: Arc<dyn EntitlementService> = Arc::new(EntitlementServiceImpl::new(
            backend,
            Arc::new(ApplicationRepo::new(pool.clone())),
        ));
        run_reaper_scenario(pool, &hydra_admin_url, &hydra_public_url, entitlements).await;
    }
}

#[cfg(feature = "keto")]
mod keto {
    use super::*;
    use sso_gateway::services::permission::PermissionBackend;
    use sso_ory_client::KetoClient;

    static KETO: tokio::sync::OnceCell<(ContainerAsync<GenericImage>, String, String)> =
        tokio::sync::OnceCell::const_new();

    async fn keto_urls() -> (String, String) {
        let (_, read_url, write_url) = KETO
            .get_or_init(|| async { support::start_keto().await.expect("keto should start") })
            .await;
        (read_url.clone(), write_url.clone())
    }

    #[tokio::test]
    async fn reaper_deletes_only_old_provisional_registrations() {
        let (database_url, hydra_admin_url, hydra_public_url) = shared_urls().await;
        let (keto_read_url, keto_write_url) = keto_urls().await;
        let pool = create_pool(&database_url, false)
            .await
            .expect("database pool should be created");
        let backend: Arc<dyn PermissionBackend> = Arc::new(
            KetoClient::new(&keto_read_url, &keto_write_url).expect("keto client should build"),
        );
        let entitlements: Arc<dyn EntitlementService> = Arc::new(EntitlementServiceImpl::new(
            backend,
            Arc::new(ApplicationRepo::new(pool.clone())),
        ));
        run_reaper_scenario(pool, &hydra_admin_url, &hydra_public_url, entitlements).await;
    }
}
