// SSO-027: tests may unwrap/expect freely; the panic/default bans target production code.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods))]

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

async fn entitlement_service() -> (EntitlementServiceImpl, String) {
    let (_, read_url, write_url) = KETO
        .get_or_init(|| async { support::start_keto().await.expect("keto should start") })
        .await;
    let backend: Arc<dyn PermissionBackend> = Arc::new(
        KetoClient::new(read_url, write_url).expect("keto client should build"),
    );
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

/// Full lifecycle on Keto: seeding, group-derived member/admin resolution
/// through subject sets, direct grants, claims, and scope ceilings.
#[tokio::test]
async fn entitlement_service_keto_lifecycle() {
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

    // The scope ceiling follows the gateway entitlement.
    let ceiling = svc.effective_scope_ceiling(&tenant, "alice").await;
    assert!(
        ceiling.iter().any(|s| s == "tenant:admin"),
        "admin ceiling expected, got {ceiling:?}"
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
    svc.revoke(&tenant, "alice", GATEWAY_APP_OBJECT, EntitlementLevel::Admin)
        .await
        .expect("revoke without grant should succeed");
}
