//! DCR maintenance: legacy-client backfill and unused-registration GC
//! (SSO-039).
//!
//! Before consent-gated first-use entitlement existed, RFC 7591 dynamic
//! client registration created only the Hydra client and an `id_mappings`
//! row — no `applications` row, no entitlement tuples — and every such
//! client 403'd at login. The startup backfill converges those legacy
//! clients: tuple-less ones are seeded with the default group links (the
//! historical shape; per-user consent history is unreconstructable) and
//! every one gets a DCR-marked `applications` row.
//!
//! The daily garbage collector reaps the other end of the lifecycle:
//! registrations that were never consented to (still no `applications` row,
//! still no tuples) older than a configurable TTL are deleted from Hydra
//! and from `id_mappings`. Ordering constraint: the GC must only run
//! alongside/after the backfill — before it, broken-but-active legacy
//! clients are indistinguishable from never-used spam.

use std::sync::Arc;
use std::time::Duration;

use tracing::{error, info, warn};

use crate::db::{
    AgentStore, ApplicationStore, DbError, IdMappingRow, IdMappingStore, REGISTRATION_SOURCE_DCR,
    TenantStore,
};
use crate::services::entitlement::EntitlementService;
use crate::services::handlers::oauth2::HydraOperations;

const BACKEND_HYDRA: &str = "hydra";

/// Outcome of the startup backfill pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackfillStats {
    /// Hydra-mapped clients examined.
    pub checked: u64,
    /// Clients seeded with the default group links (previously tuple-less).
    pub seeded: u64,
    /// DCR-marked `applications` rows created.
    pub rows_created: u64,
    /// Clients skipped because an `applications` row already exists.
    pub skipped_existing_rows: u64,
    /// Clients skipped because they are gateway-owned agents.
    pub skipped_agents: u64,
    /// Per-client/per-tenant failures (logged; the pass continued).
    pub errors: u64,
}

/// Outcome of one unused-registration GC run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReapStats {
    /// Hydra-mapped registrations examined.
    pub checked: u64,
    /// Registrations deleted (Hydra client + mapping).
    pub reaped: u64,
    /// Registrations younger than the TTL.
    pub skipped_young: u64,
    /// Registrations with an `applications` row (consented or admin-created).
    pub skipped_existing_rows: u64,
    /// Registrations belonging to gateway-owned agents.
    pub skipped_agents: u64,
    /// Registrations that gained tuples or a row between the scan and the
    /// delete (a concurrent first-use consent); left alone.
    pub skipped_now_in_use: u64,
    /// Per-client/per-tenant failures (logged; the run continued).
    pub errors: u64,
}

/// Maintenance operations for RFC 7591 dynamically registered clients.
pub struct DcrMaintenance {
    mappings: Arc<dyn IdMappingStore>,
    applications: Arc<dyn ApplicationStore>,
    entitlements: Arc<dyn EntitlementService>,
    hydra: Arc<dyn HydraOperations>,
    tenants: Arc<dyn TenantStore>,
    agents: Arc<dyn AgentStore>,
    default_groups: Vec<String>,
    ttl: Duration,
}

/// Per-client outcome of the backfill.
enum BackfillOutcome {
    /// Already had an `applications` row; nothing to do.
    ExistingRow,
    /// Gateway-owned agent; entitlements are meaningless for machine clients.
    Agent,
    /// Was tuple-less: seeded and given its DCR row.
    Seeded,
    /// Already had tuples (e.g. manually patched): given its DCR row, NOT
    /// reseeded — "has tuples" is the revocation-survives-restart signal.
    RowOnly,
}

/// Per-client outcome of the reaper.
enum ReapOutcome {
    Reaped,
    Young,
    ExistingRow,
    Agent,
    /// Tuples or a row appeared between the scan and the delete.
    NowInUse,
}

impl DcrMaintenance {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mappings: Arc<dyn IdMappingStore>,
        applications: Arc<dyn ApplicationStore>,
        entitlements: Arc<dyn EntitlementService>,
        hydra: Arc<dyn HydraOperations>,
        tenants: Arc<dyn TenantStore>,
        agents: Arc<dyn AgentStore>,
        default_groups: Vec<String>,
        ttl: Duration,
    ) -> Self {
        Self {
            mappings,
            applications,
            entitlements,
            hydra,
            tenants,
            agents,
            default_groups,
            ttl,
        }
    }

    /// Startup convergence pass over every Hydra-mapped client of every
    /// tenant (SSO-039 §5).
    ///
    /// Idempotent and safe under concurrent replicas: seeding uses
    /// `ensure_tuples`, and a duplicate `applications` insert loses the race
    /// harmlessly. Per-client errors are logged and counted; one bad client
    /// never aborts the pass, and the next boot retries — partial state
    /// converges by construction.
    pub async fn backfill_legacy_dcr_clients(&self) -> BackfillStats {
        let mut stats = BackfillStats::default();
        let tenants = match self.tenants.list().await {
            Ok(tenants) => tenants,
            Err(err) => {
                error!(error = %err, "dcr backfill: failed to list tenants");
                stats.errors += 1;
                return stats;
            }
        };
        for tenant in tenants {
            let public_ids = match self
                .mappings
                .list_public_ids(&tenant.id, BACKEND_HYDRA)
                .await
            {
                Ok(ids) => ids,
                Err(err) => {
                    error!(tenant_id = %tenant.id, error = %err, "dcr backfill: failed to list hydra mappings");
                    stats.errors += 1;
                    continue;
                }
            };
            for public_id in public_ids {
                stats.checked += 1;
                match self.backfill_client(&tenant.id, &public_id).await {
                    Ok(BackfillOutcome::ExistingRow) => stats.skipped_existing_rows += 1,
                    Ok(BackfillOutcome::Agent) => stats.skipped_agents += 1,
                    Ok(BackfillOutcome::Seeded) => {
                        stats.seeded += 1;
                        stats.rows_created += 1;
                    }
                    Ok(BackfillOutcome::RowOnly) => stats.rows_created += 1,
                    Err(err) => {
                        warn!(tenant_id = %tenant.id, public_id = %public_id, error = %err, "dcr backfill: client failed; continuing");
                        stats.errors += 1;
                    }
                }
            }
        }
        info!(
            checked = stats.checked,
            seeded = stats.seeded,
            rows_created = stats.rows_created,
            skipped_existing_rows = stats.skipped_existing_rows,
            skipped_agents = stats.skipped_agents,
            errors = stats.errors,
            "dcr legacy client backfill completed"
        );
        stats
    }

    async fn backfill_client(
        &self,
        tenant_id: &str,
        public_id: &str,
    ) -> Result<BackfillOutcome, String> {
        if self.application_row_exists(tenant_id, public_id).await? {
            return Ok(BackfillOutcome::ExistingRow);
        }
        if self.is_agent(public_id).await? {
            return Ok(BackfillOutcome::Agent);
        }
        let mut seeded = false;
        if !self
            .entitlements
            .has_any_tuples(tenant_id, public_id)
            .await
            .map_err(|err| format!("entitlement tuple read: {err}"))?
        {
            self.entitlements
                .seed_application(tenant_id, public_id, &self.default_groups)
                .await
                .map_err(|err| format!("entitlement seed: {err}"))?;
            seeded = true;
            info!(
                target: "sso_gateway::audit",
                tenant_id = tenant_id,
                application = public_id,
                action = "dcr.legacy_client_backfilled",
                outcome = "success",
                groups = ?self.default_groups,
                "seeded entitlements for legacy DCR client"
            );
        }
        // The row is ensured even when tuples already existed (the manually
        // patched case): it gets its DCR row but is NOT reseeded.
        self.ensure_dcr_row(tenant_id, public_id).await?;
        Ok(if seeded {
            BackfillOutcome::Seeded
        } else {
            BackfillOutcome::RowOnly
        })
    }

    /// Create the DCR-marked `applications` row, tolerating a duplicate-row
    /// race with a concurrently booting replica.
    async fn ensure_dcr_row(&self, tenant_id: &str, public_id: &str) -> Result<(), String> {
        match self
            .applications
            .create(tenant_id, public_id, false, REGISTRATION_SOURCE_DCR)
            .await
        {
            Ok(_) => Ok(()),
            Err(err) => {
                // No unique-violation variant surfaces from the store; a
                // lost create race is confirmed by the row now existing.
                if self.application_row_exists(tenant_id, public_id).await? {
                    Ok(())
                } else {
                    Err(format!("application row create: {err}"))
                }
            }
        }
    }

    async fn application_row_exists(
        &self,
        tenant_id: &str,
        public_id: &str,
    ) -> Result<bool, String> {
        match self.applications.get(tenant_id, public_id).await {
            Ok(_) => Ok(true),
            Err(DbError::ApplicationNotFound) => Ok(false),
            Err(err) => Err(format!("application row lookup: {err}")),
        }
    }

    async fn is_agent(&self, public_id: &str) -> Result<bool, String> {
        match self.agents.get_status(public_id).await {
            Ok(_) => Ok(true),
            Err(DbError::AgentNotFound) => Ok(false),
            Err(err) => Err(format!("agent lookup: {err}")),
        }
    }

    /// One GC pass over provisional registrations (SSO-039 §1): Hydra-mapped
    /// clients with no `applications` row and no tuples whose mapping is
    /// older than the configured TTL are deleted from Hydra and from
    /// `id_mappings`. Per-client errors are logged and counted; the run
    /// always completes.
    pub async fn reap_unused_registrations(&self) -> ReapStats {
        let mut stats = ReapStats::default();
        let ttl = match time::Duration::try_from(self.ttl) {
            Ok(ttl) => ttl,
            Err(err) => {
                error!(error = %err, "dcr gc: invalid ttl; aborting run");
                stats.errors += 1;
                return stats;
            }
        };
        let tenants = match self.tenants.list().await {
            Ok(tenants) => tenants,
            Err(err) => {
                error!(error = %err, "dcr gc: failed to list tenants");
                stats.errors += 1;
                return stats;
            }
        };
        for tenant in tenants {
            let rows = match self.mappings.list_mappings(&tenant.id, BACKEND_HYDRA).await {
                Ok(rows) => rows,
                Err(err) => {
                    error!(tenant_id = %tenant.id, error = %err, "dcr gc: failed to list hydra mappings");
                    stats.errors += 1;
                    continue;
                }
            };
            for row in rows {
                stats.checked += 1;
                match self.reap_registration(&tenant.id, &row, ttl).await {
                    Ok(ReapOutcome::Reaped) => stats.reaped += 1,
                    Ok(ReapOutcome::Young) => stats.skipped_young += 1,
                    Ok(ReapOutcome::ExistingRow) => stats.skipped_existing_rows += 1,
                    Ok(ReapOutcome::Agent) => stats.skipped_agents += 1,
                    Ok(ReapOutcome::NowInUse) => stats.skipped_now_in_use += 1,
                    Err(err) => {
                        warn!(tenant_id = %tenant.id, public_id = %row.public_id, error = %err, "dcr gc: client failed; continuing");
                        stats.errors += 1;
                    }
                }
            }
        }
        info!(
            checked = stats.checked,
            reaped = stats.reaped,
            skipped_young = stats.skipped_young,
            skipped_existing_rows = stats.skipped_existing_rows,
            skipped_agents = stats.skipped_agents,
            skipped_now_in_use = stats.skipped_now_in_use,
            errors = stats.errors,
            "dcr unused registration gc completed"
        );
        stats
    }

    async fn reap_registration(
        &self,
        tenant_id: &str,
        row: &IdMappingRow,
        ttl: time::Duration,
    ) -> Result<ReapOutcome, String> {
        let age = time::OffsetDateTime::now_utc() - row.created_at;
        if age < ttl {
            return Ok(ReapOutcome::Young);
        }
        if self
            .application_row_exists(tenant_id, &row.public_id)
            .await?
        {
            return Ok(ReapOutcome::ExistingRow);
        }
        if self.is_agent(&row.public_id).await? {
            return Ok(ReapOutcome::Agent);
        }
        // Race with a concurrent first-use consent: re-check entitlement
        // tuples and the applications row immediately before deleting.
        if self
            .entitlements
            .has_any_tuples(tenant_id, &row.public_id)
            .await
            .map_err(|err| format!("entitlement tuple read: {err}"))?
            || self
                .application_row_exists(tenant_id, &row.public_id)
                .await?
        {
            return Ok(ReapOutcome::NowInUse);
        }

        // Delete the Hydra client first so it stops issuing tokens even if
        // the mapping delete fails; an already-gone client is not an error
        // (DELETE is idempotent — same idiom as delete_registered_client).
        match self.hydra.delete_oauth2_client(&row.ory_global_id).await {
            Ok(()) => {}
            Err(sso_ory_client::error::OryClientError::Ory { status: 404, .. }) => {}
            Err(err) => return Err(format!("hydra client delete: {err}")),
        }
        match self
            .mappings
            .delete(tenant_id, BACKEND_HYDRA, &row.public_id)
            .await
        {
            Ok(()) | Err(DbError::MappingNotFound) => {}
            Err(err) => return Err(format!("mapping delete: {err}")),
        }
        info!(
            target: "sso_gateway::audit",
            tenant_id = tenant_id,
            application = %row.public_id,
            action = "dcr.registration_reaped",
            outcome = "success",
            age_seconds = age.whole_seconds(),
            "reaped unused DCR registration"
        );
        Ok(ReapOutcome::Reaped)
    }

    /// Spawn the daily GC worker.
    ///
    /// The first run happens one full `interval` AFTER startup — the startup
    /// backfill always runs first (plain `sleep` + loop rather than
    /// `tokio::time::interval`, whose first tick fires immediately). A panicking
    /// run is logged and the loop continues.
    pub fn spawn_gc_worker(self: Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                info!("dcr gc run starting");
                // Run each pass on its own task so a panic lands on the
                // JoinHandle instead of killing the worker.
                let worker = self.clone();
                let run = tokio::spawn(async move { worker.reap_unused_registrations().await });
                match run.await {
                    Ok(stats) => info!(
                        checked = stats.checked,
                        reaped = stats.reaped,
                        errors = stats.errors,
                        "dcr gc run completed"
                    ),
                    Err(err) => {
                        error!(error = %err, "dcr gc run panicked; worker continues")
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{AgentRow, MemoryApplicationStore, MemoryIdMappingStore, TenantRow};
    use crate::services::entitlement::EntitlementLevel;
    use serde_json::Value;
    use sso_ory_client::error::OryClientError;
    use std::collections::HashSet;
    use std::sync::Mutex;
    use sunbeam_g2v::error::ServiceError;

    const TENANT: &str = "tenant-1";

    // ---------------------------------------------------------------------
    // Test doubles
    // ---------------------------------------------------------------------

    struct StubTenantStore {
        tenants: Vec<TenantRow>,
    }

    fn tenant_row(id: &str) -> TenantRow {
        TenantRow {
            id: id.to_string(),
            slug: id.to_string(),
            display_name: id.to_string(),
            is_system: false,
            settings: Value::Null,
        }
    }

    #[async_trait::async_trait]
    impl TenantStore for StubTenantStore {
        async fn create(
            &self,
            _slug: &str,
            _display_name: &str,
            _settings: Value,
        ) -> Result<TenantRow, DbError> {
            unimplemented!()
        }

        async fn get_by_id(&self, _id: &str) -> Result<TenantRow, DbError> {
            unimplemented!()
        }

        async fn list(&self) -> Result<Vec<TenantRow>, DbError> {
            Ok(self.tenants.clone())
        }
    }

    #[derive(Default)]
    struct StubAgentStore {
        agents: Mutex<HashSet<String>>,
    }

    #[async_trait::async_trait]
    impl AgentStore for StubAgentStore {
        async fn create(
            &self,
            _tenant_id: &str,
            _owner_identity_id: Option<&str>,
            _name: &str,
        ) -> Result<AgentRow, DbError> {
            unimplemented!()
        }

        async fn get(&self, _tenant_id: &str, _id: &str) -> Result<AgentRow, DbError> {
            unimplemented!()
        }

        async fn get_status(&self, id: &str) -> Result<String, DbError> {
            let agents = self.agents.lock().unwrap();
            match agents.contains(id) {
                true => Ok("active".to_string()),
                false => Err(DbError::AgentNotFound),
            }
        }

        async fn set_name(
            &self,
            _tenant_id: &str,
            _id: &str,
            _name: &str,
        ) -> Result<AgentRow, DbError> {
            unimplemented!()
        }

        async fn set_status(
            &self,
            _tenant_id: &str,
            _id: &str,
            _status: &str,
        ) -> Result<AgentRow, DbError> {
            unimplemented!()
        }

        async fn delete(&self, _tenant_id: &str, _id: &str) -> Result<(), DbError> {
            unimplemented!()
        }

        async fn list_page(
            &self,
            _tenant_id: &str,
            _limit: u32,
            _after: Option<(time::OffsetDateTime, String)>,
        ) -> Result<(Vec<AgentRow>, i64), DbError> {
            unimplemented!()
        }
    }

    /// Entitlement double that tracks which (tenant, app) pairs carry tuples;
    /// `seed_application` populates them, mirroring the real service.
    #[derive(Default)]
    struct RecordingEntitlements {
        tuples: Mutex<HashSet<(String, String)>>,
        seeded: Mutex<Vec<(String, String, Vec<String>)>>,
        fail_seed_for: Mutex<HashSet<String>>,
    }

    impl RecordingEntitlements {
        fn add_tuple(&self, tenant_id: &str, app: &str) {
            self.tuples
                .lock()
                .unwrap()
                .insert((tenant_id.to_string(), app.to_string()));
        }

        fn fail_seed_for(&self, app: &str) {
            self.fail_seed_for.lock().unwrap().insert(app.to_string());
        }
    }

    #[async_trait::async_trait]
    impl EntitlementService for RecordingEntitlements {
        async fn ensure_namespace(&self, _tenant_id: &str) -> Result<(), ServiceError> {
            Ok(())
        }

        async fn seed_application(
            &self,
            tenant_id: &str,
            app_public_id: &str,
            groups: &[String],
        ) -> Result<(), ServiceError> {
            if self.fail_seed_for.lock().unwrap().contains(app_public_id) {
                return Err(ServiceError::Internal("seed failed".to_string()));
            }
            self.seeded.lock().unwrap().push((
                tenant_id.to_string(),
                app_public_id.to_string(),
                groups.to_vec(),
            ));
            self.add_tuple(tenant_id, app_public_id);
            Ok(())
        }

        async fn remove_application(
            &self,
            _tenant_id: &str,
            _app_public_id: &str,
        ) -> Result<(), ServiceError> {
            Ok(())
        }

        async fn check(
            &self,
            _tenant_id: &str,
            _identity_id: &str,
            _app_public_id: &str,
            _relation: &str,
        ) -> Result<bool, ServiceError> {
            Ok(false)
        }

        async fn has_any_tuples(
            &self,
            tenant_id: &str,
            app_public_id: &str,
        ) -> Result<bool, ServiceError> {
            Ok(self
                .tuples
                .lock()
                .unwrap()
                .contains(&(tenant_id.to_string(), app_public_id.to_string())))
        }

        async fn effective_scope_ceiling(
            &self,
            _tenant_id: &str,
            _identity_id: &str,
        ) -> Vec<String> {
            vec![]
        }

        async fn grant(
            &self,
            _tenant_id: &str,
            _identity_id: &str,
            _app_public_id: &str,
            _level: EntitlementLevel,
        ) -> Result<(), ServiceError> {
            Ok(())
        }

        async fn revoke(
            &self,
            _tenant_id: &str,
            _identity_id: &str,
            _app_public_id: &str,
            _level: EntitlementLevel,
        ) -> Result<(), ServiceError> {
            Ok(())
        }

        async fn set_group_membership(
            &self,
            _tenant_id: &str,
            _group_name: &str,
            _identity_id: &str,
            _member: bool,
        ) -> Result<(), ServiceError> {
            Ok(())
        }

        async fn remove_all_for_identity(
            &self,
            _tenant_id: &str,
            _identity_id: &str,
        ) -> Result<(), ServiceError> {
            Ok(())
        }

        async fn mint_claim(
            &self,
            _tenant_id: &str,
            _identity_id: &str,
            _app_public_id: &str,
        ) -> Value {
            Value::Null
        }
    }

    /// Hydra double recording deletes; individual clients can be made to 404
    /// or fail on delete.
    #[derive(Default)]
    struct RecordingHydra {
        deleted: Mutex<Vec<String>>,
        gone: Mutex<HashSet<String>>,
        fail_delete_for: Mutex<HashSet<String>>,
    }

    #[async_trait::async_trait]
    impl HydraOperations for RecordingHydra {
        async fn authorize(
            &self,
            _query: Vec<(String, String)>,
            _cookie: Option<&str>,
        ) -> Result<Value, OryClientError> {
            unimplemented!()
        }

        async fn token(
            &self,
            _form: Vec<(String, String)>,
            _client_credentials: Option<(String, String)>,
        ) -> Result<Value, OryClientError> {
            unimplemented!()
        }

        async fn device(
            &self,
            _path: &str,
            _form: Vec<(String, String)>,
            _client_credentials: Option<(String, String)>,
        ) -> Result<Value, OryClientError> {
            unimplemented!()
        }

        async fn get_device_verify(
            &self,
            _query: Vec<(String, String)>,
            _cookie: Option<&str>,
        ) -> Result<Value, OryClientError> {
            unimplemented!()
        }

        async fn userinfo(&self, _token: &str) -> Result<Value, OryClientError> {
            unimplemented!()
        }

        async fn introspect_token(&self, _token: &str) -> Result<Value, OryClientError> {
            unimplemented!()
        }

        async fn verify_client_credentials(
            &self,
            _client_id: &str,
            _client_secret: &str,
        ) -> Result<bool, OryClientError> {
            unimplemented!()
        }

        async fn revoke(&self, _form: Vec<(String, String)>) -> Result<(), OryClientError> {
            unimplemented!()
        }

        async fn create_oauth2_client(&self, _payload: Value) -> Result<Value, OryClientError> {
            unimplemented!()
        }

        async fn get_oauth2_client(&self, _id: &str) -> Result<Value, OryClientError> {
            unimplemented!()
        }

        async fn delete_oauth2_client(&self, id: &str) -> Result<(), OryClientError> {
            if self.fail_delete_for.lock().unwrap().contains(id) {
                return Err(OryClientError::Ory {
                    status: 500,
                    message: "hydra exploded".to_string(),
                });
            }
            if self.gone.lock().unwrap().contains(id) {
                return Err(OryClientError::Ory {
                    status: 404,
                    message: "not found".to_string(),
                });
            }
            self.deleted.lock().unwrap().push(id.to_string());
            Ok(())
        }

        async fn get_json(&self, _url: reqwest::Url) -> Result<Value, OryClientError> {
            unimplemented!()
        }

        fn public_url(&self) -> &reqwest::Url {
            static URL: std::sync::OnceLock<reqwest::Url> = std::sync::OnceLock::new();
            URL.get_or_init(|| reqwest::Url::parse("http://127.0.0.1:4444").unwrap())
        }
    }

    // ---------------------------------------------------------------------
    // Harness
    // ---------------------------------------------------------------------

    struct Harness {
        maintenance: Arc<DcrMaintenance>,
        mappings: Arc<MemoryIdMappingStore>,
        applications: Arc<MemoryApplicationStore>,
        entitlements: Arc<RecordingEntitlements>,
        hydra: Arc<RecordingHydra>,
        agents: Arc<StubAgentStore>,
    }

    fn harness() -> Harness {
        harness_with_ttl(Duration::from_secs(7 * 86_400))
    }

    fn harness_with_ttl(ttl: Duration) -> Harness {
        let mappings = Arc::new(MemoryIdMappingStore::default());
        let applications = Arc::new(MemoryApplicationStore::default());
        let entitlements = Arc::new(RecordingEntitlements::default());
        let hydra = Arc::new(RecordingHydra::default());
        let agents = Arc::new(StubAgentStore::default());
        let tenants = Arc::new(StubTenantStore {
            tenants: vec![tenant_row(TENANT)],
        });
        let maintenance = Arc::new(DcrMaintenance::new(
            mappings.clone(),
            applications.clone(),
            entitlements.clone(),
            hydra.clone(),
            tenants,
            agents.clone(),
            vec!["employees".to_string()],
            ttl,
        ));
        Harness {
            maintenance,
            mappings,
            applications,
            entitlements,
            hydra,
            agents,
        }
    }

    async fn add_mapping(h: &Harness, public_id: &str, ory_id: &str) {
        h.mappings
            .create(TENANT, BACKEND_HYDRA, public_id, ory_id)
            .await
            .unwrap();
    }

    async fn add_old_mapping(h: &Harness, public_id: &str, ory_id: &str, age: Duration) {
        let created_at = time::OffsetDateTime::now_utc() - time::Duration::try_from(age).unwrap();
        h.mappings
            .create_at(TENANT, BACKEND_HYDRA, public_id, ory_id, created_at)
            .await
            .unwrap();
    }

    async fn has_row(h: &Harness, public_id: &str) -> bool {
        h.applications.get_by_public_id(public_id).await.is_ok()
    }

    // ---------------------------------------------------------------------
    // Backfill
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn backfill_seeds_tupleless_legacy_client_and_writes_dcr_row() {
        let h = harness();
        add_mapping(&h, "app-1", "ory-1").await;

        let stats = h.maintenance.backfill_legacy_dcr_clients().await;

        assert_eq!(stats.checked, 1);
        assert_eq!(stats.seeded, 1);
        assert_eq!(stats.rows_created, 1);
        assert_eq!(stats.errors, 0);
        assert_eq!(
            h.entitlements.seeded.lock().unwrap().as_slice(),
            &[(
                TENANT.to_string(),
                "app-1".to_string(),
                vec!["employees".to_string()]
            )]
        );
        let row = h.applications.get(TENANT, "app-1").await.unwrap();
        assert_eq!(row.registration_source, REGISTRATION_SOURCE_DCR);
        assert!(!row.cross_tenant);
    }

    #[tokio::test]
    async fn backfill_does_not_reseed_tuple_having_client_but_writes_row() {
        let h = harness();
        add_mapping(&h, "app-1", "ory-1").await;
        // The manually-patched prod client: tuples exist, no row.
        h.entitlements.add_tuple(TENANT, "app-1");

        let stats = h.maintenance.backfill_legacy_dcr_clients().await;

        assert_eq!(
            stats.seeded, 0,
            "a client with tuples must never be reseeded"
        );
        assert_eq!(stats.rows_created, 1);
        assert!(h.entitlements.seeded.lock().unwrap().is_empty());
        assert!(has_row(&h, "app-1").await);
    }

    #[tokio::test]
    async fn backfill_skips_admin_apps_and_agents() {
        let h = harness();
        add_mapping(&h, "admin-app", "ory-1").await;
        add_mapping(&h, "agent-1", "ory-2").await;
        h.applications
            .create(
                TENANT,
                "admin-app",
                false,
                crate::db::REGISTRATION_SOURCE_ADMIN,
            )
            .await
            .unwrap();
        h.agents
            .agents
            .lock()
            .unwrap()
            .insert("agent-1".to_string());

        let stats = h.maintenance.backfill_legacy_dcr_clients().await;

        assert_eq!(stats.checked, 2);
        assert_eq!(stats.skipped_existing_rows, 1);
        assert_eq!(stats.skipped_agents, 1);
        assert_eq!(stats.seeded, 0);
        assert_eq!(stats.rows_created, 0);
        assert!(h.entitlements.seeded.lock().unwrap().is_empty());
        assert!(!has_row(&h, "agent-1").await);
    }

    #[tokio::test]
    async fn backfill_tolerates_duplicate_row_race() {
        let h = harness();
        add_mapping(&h, "app-1", "ory-1").await;

        // First ensure creates the row; a concurrent replica's ensure finds
        // the create rejected but the row present, and tolerates the race.
        h.maintenance.ensure_dcr_row(TENANT, "app-1").await.unwrap();
        h.maintenance.ensure_dcr_row(TENANT, "app-1").await.unwrap();
        assert!(has_row(&h, "app-1").await);
    }

    #[tokio::test]
    async fn backfill_continues_past_per_client_error_and_next_pass_retries() {
        let h = harness();
        add_mapping(&h, "app-bad", "ory-2").await;
        add_mapping(&h, "app-ok", "ory-3").await;
        h.entitlements.fail_seed_for("app-bad");

        let stats = h.maintenance.backfill_legacy_dcr_clients().await;

        assert_eq!(stats.checked, 2);
        assert_eq!(
            stats.errors, 1,
            "the failing client must not abort the pass"
        );
        assert_eq!(stats.seeded, 1, "the healthy client is still seeded");
        assert!(has_row(&h, "app-ok").await);
        // The failed client got no row; the next pass retries it.
        assert!(!has_row(&h, "app-bad").await);
        h.entitlements.fail_seed_for.lock().unwrap().clear();
        let retry = h.maintenance.backfill_legacy_dcr_clients().await;
        assert_eq!(retry.seeded, 1);
        assert_eq!(retry.errors, 0);
        assert!(has_row(&h, "app-bad").await);
    }

    #[tokio::test]
    async fn backfill_second_run_is_a_no_op() {
        let h = harness();
        add_mapping(&h, "app-1", "ory-1").await;

        h.maintenance.backfill_legacy_dcr_clients().await;
        let stats = h.maintenance.backfill_legacy_dcr_clients().await;

        assert_eq!(stats.seeded, 0);
        assert_eq!(stats.rows_created, 0);
        assert_eq!(stats.skipped_existing_rows, 1);
        assert_eq!(h.entitlements.seeded.lock().unwrap().len(), 1);
    }

    // ---------------------------------------------------------------------
    // Reaper
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn reaper_deletes_old_provisional_registration() {
        let h = harness();
        add_old_mapping(&h, "app-old", "ory-old", Duration::from_secs(8 * 86_400)).await;

        let stats = h.maintenance.reap_unused_registrations().await;

        assert_eq!(stats.checked, 1);
        assert_eq!(stats.reaped, 1);
        assert_eq!(stats.errors, 0);
        assert_eq!(
            h.hydra.deleted.lock().unwrap().as_slice(),
            &["ory-old".to_string()]
        );
        assert!(matches!(
            h.mappings
                .get_ory_id(TENANT, BACKEND_HYDRA, "app-old")
                .await,
            Err(DbError::MappingNotFound)
        ));
    }

    #[tokio::test]
    async fn reaper_skips_young_registrations() {
        let h = harness();
        add_mapping(&h, "app-young", "ory-young").await;

        let stats = h.maintenance.reap_unused_registrations().await;

        assert_eq!(stats.skipped_young, 1);
        assert_eq!(stats.reaped, 0);
        assert!(h.hydra.deleted.lock().unwrap().is_empty());
        assert!(
            h.mappings
                .list_public_ids(TENANT, BACKEND_HYDRA)
                .await
                .unwrap()
                .len()
                == 1
        );
    }

    #[tokio::test]
    async fn reaper_skips_row_having_and_agent_clients() {
        let h = harness();
        add_old_mapping(
            &h,
            "app-consented",
            "ory-1",
            Duration::from_secs(8 * 86_400),
        )
        .await;
        add_old_mapping(&h, "agent-1", "ory-2", Duration::from_secs(8 * 86_400)).await;
        h.applications
            .create(TENANT, "app-consented", false, REGISTRATION_SOURCE_DCR)
            .await
            .unwrap();
        h.agents
            .agents
            .lock()
            .unwrap()
            .insert("agent-1".to_string());

        let stats = h.maintenance.reap_unused_registrations().await;

        assert_eq!(stats.skipped_existing_rows, 1);
        assert_eq!(stats.skipped_agents, 1);
        assert_eq!(stats.reaped, 0);
        assert!(h.hydra.deleted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn reaper_rechecks_and_skips_when_tuples_appear_before_delete() {
        let h = harness_with_ttl(Duration::ZERO);
        // No row, young or old — the age check passes with a zero TTL; the
        // tuple re-check is the guard under test.
        add_mapping(&h, "app-live", "ory-live").await;
        // A first-use consent lands between the scan and the delete.
        h.entitlements.add_tuple(TENANT, "app-live");

        let stats = h.maintenance.reap_unused_registrations().await;

        assert_eq!(stats.skipped_now_in_use, 1);
        assert_eq!(stats.reaped, 0);
        assert!(h.hydra.deleted.lock().unwrap().is_empty());
        assert!(
            h.mappings
                .list_public_ids(TENANT, BACKEND_HYDRA)
                .await
                .unwrap()
                .len()
                == 1
        );
    }

    #[tokio::test]
    async fn reaper_tolerates_hydra_404_and_per_client_failure() {
        let h = harness();
        add_old_mapping(&h, "app-gone", "ory-gone", Duration::from_secs(8 * 86_400)).await;
        add_old_mapping(&h, "app-bad", "ory-bad", Duration::from_secs(8 * 86_400)).await;
        add_old_mapping(&h, "app-ok", "ory-ok", Duration::from_secs(8 * 86_400)).await;
        h.hydra.gone.lock().unwrap().insert("ory-gone".to_string());
        h.hydra
            .fail_delete_for
            .lock()
            .unwrap()
            .insert("ory-bad".to_string());

        let stats = h.maintenance.reap_unused_registrations().await;

        assert_eq!(stats.checked, 3);
        assert_eq!(
            stats.reaped, 2,
            "404 counts as reaped; the healthy one deletes"
        );
        assert_eq!(stats.errors, 1);
        // The failed client keeps its mapping for the next run.
        assert!(
            h.mappings
                .get_ory_id(TENANT, BACKEND_HYDRA, "app-bad")
                .await
                .is_ok()
        );
        assert!(matches!(
            h.mappings
                .get_ory_id(TENANT, BACKEND_HYDRA, "app-gone")
                .await,
            Err(DbError::MappingNotFound)
        ));
    }

    // ---------------------------------------------------------------------
    // Worker
    // ---------------------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn worker_first_run_happens_only_after_one_interval() {
        let h = harness();
        add_old_mapping(&h, "app-old", "ory-old", Duration::from_secs(8 * 86_400)).await;
        let interval = Duration::from_secs(24 * 3600);
        let handle = h.maintenance.clone().spawn_gc_worker(interval);

        // Paused time does not advance on its own here: no run has happened.
        tokio::task::yield_now().await;
        assert!(h.hydra.deleted.lock().unwrap().is_empty());

        // Just before the interval elapses: still nothing.
        tokio::time::advance(interval - Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(
            h.hydra.deleted.lock().unwrap().is_empty(),
            "the first reap must wait one full interval (the startup backfill runs first)"
        );

        // Cross the interval: the first run fires.
        tokio::time::advance(Duration::from_secs(2)).await;
        // Let the worker and its nested run task execute to completion.
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            h.hydra.deleted.lock().unwrap().as_slice(),
            &["ory-old".to_string()]
        );
        handle.abort();
    }
}
