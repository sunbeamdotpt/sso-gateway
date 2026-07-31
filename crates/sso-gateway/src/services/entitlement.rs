use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;
use tracing::{info, warn};

use crate::auth::{
    SCOPE_AGENT_ADMIN, SCOPE_AGENT_READ, SCOPE_APPLICATION_ADMIN, SCOPE_APPLICATION_READ,
    SCOPE_IDENTITY_ADMIN, SCOPE_IDENTITY_READ, SCOPE_PERMISSION_ADMIN, SCOPE_PERMISSION_READ,
    SCOPE_SCIM_ADMIN, SCOPE_SCIM_READ, SCOPE_TENANT_ADMIN, SCOPE_TENANT_READ,
};
use crate::db::ApplicationStore;
use crate::services::permission::{
    PermissionBackend, PermissionBackendError, QueryOptions, RelationTupleKey,
};
use sunbeam_g2v::error::ServiceError;

/// Reserved OpenFGA namespace for application entitlements.
pub const ENTITLEMENT_NAMESPACE: &str = "entitlements";

/// Well-known object name for the gateway's own API in the entitlement namespace.
pub const GATEWAY_APP_OBJECT: &str = "sso-gateway";

const GROUP_TYPE: &str = "group";
const APPLICATION_TYPE: &str = "application";

const MEMBER_REL: &str = "member";
const ADMIN_REL: &str = "admin";
const GROUP_REL: &str = "group";

/// Levels at which a user may be entitled to an application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntitlementLevel {
    Member,
    Admin,
}

impl EntitlementLevel {
    fn relation(&self) -> &'static str {
        match self {
            EntitlementLevel::Member => MEMBER_REL,
            EntitlementLevel::Admin => ADMIN_REL,
        }
    }
}

/// Entitlement-related operations abstracted for testing and backend swaps.
#[async_trait]
pub trait EntitlementService: Send + Sync + 'static {
    /// Ensure the entitlement namespace (store + model) exists for the tenant.
    async fn ensure_namespace(&self, tenant_id: &str) -> Result<(), ServiceError>;

    /// Seed the application object and default group links after an app is
    /// registered. `groups` contains group names (e.g. `["employees"]`) that
    /// receive member-level access to the app.
    async fn seed_application(
        &self,
        tenant_id: &str,
        app_public_id: &str,
        groups: &[String],
    ) -> Result<(), ServiceError>;

    /// Remove all entitlement tuples for an application (e.g. on retirement).
    async fn remove_application(&self, tenant_id: &str, app_public_id: &str) -> Result<(), ServiceError>;

    /// Check whether `identity_id` has at least `relation` (`member` or `admin`)
    /// on `app_public_id`.
    async fn check(
        &self,
        tenant_id: &str,
        identity_id: &str,
        app_public_id: &str,
        relation: &str,
    ) -> Result<bool, ServiceError>;

    /// Convenience check for member access.
    async fn is_member(
        &self,
        tenant_id: &str,
        identity_id: &str,
        app_public_id: &str,
    ) -> Result<bool, ServiceError> {
        self.check(tenant_id, identity_id, app_public_id, MEMBER_REL).await
    }

    /// Return the effective OAuth2 scope ceiling for `identity_id` in the
    /// tenant, derived from their entitlement on the gateway application object.
    async fn effective_scope_ceiling(&self, tenant_id: &str, identity_id: &str) -> Vec<String>;

    /// Grant an explicit entitlement to a user.
    async fn grant(
        &self,
        tenant_id: &str,
        identity_id: &str,
        app_public_id: &str,
        level: EntitlementLevel,
    ) -> Result<(), ServiceError>;

    /// Revoke an explicit entitlement from a user.
    async fn revoke(
        &self,
        tenant_id: &str,
        identity_id: &str,
        app_public_id: &str,
        level: EntitlementLevel,
    ) -> Result<(), ServiceError>;

    /// Add or remove a user's membership in a group.
    async fn set_group_membership(
        &self,
        tenant_id: &str,
        group_name: &str,
        identity_id: &str,
        member: bool,
    ) -> Result<(), ServiceError>;

    /// Remove all explicit and group-derived entitlements for an identity.
    /// Used when a user is disabled.
    async fn remove_all_for_identity(&self, tenant_id: &str, identity_id: &str) -> Result<(), ServiceError>;

    /// Mint the per-client entitlement claim for `app_public_id`. Returns a
    /// JSON object like `{"entitlements": {"kanban": ["member", "admin"]}}`
    /// containing only the requested application's entry.
    async fn mint_claim(
        &self,
        tenant_id: &str,
        identity_id: &str,
        app_public_id: &str,
    ) -> Value;
}

/// Default implementation backed by the configured `PermissionBackend`.
pub struct EntitlementServiceImpl {
    backend: Arc<dyn PermissionBackend>,
    applications: Arc<dyn ApplicationStore>,
}

impl EntitlementServiceImpl {
    pub fn new(
        backend: Arc<dyn PermissionBackend>,
        applications: Arc<dyn ApplicationStore>,
    ) -> Self {
        Self {
            backend,
            applications,
        }
    }
}

#[async_trait]
impl EntitlementService for EntitlementServiceImpl {
    async fn ensure_namespace(&self, tenant_id: &str) -> Result<(), ServiceError> {
        self.backend
            .ensure_model(tenant_id, ENTITLEMENT_NAMESPACE, &entitlement_model())
            .await
            .map_err(map_backend_error)?;
        info!(tenant_id, "entitlement namespace ensured");
        Ok(())
    }

    async fn seed_application(
        &self,
        tenant_id: &str,
        app_public_id: &str,
        groups: &[String],
    ) -> Result<(), ServiceError> {
        self.ensure_namespace(tenant_id).await?;

        let mut writes = Vec::new();

        // Ensure the application object exists. We do not need a tuple for the
        // object itself; OpenFGA creates objects implicitly when tuples reference
        // them, but writing a self-referential tuple makes existence observable.
        writes.push(tuple_key(
            ENTITLEMENT_NAMESPACE,
            app_public_id,
            GROUP_REL,
            &format!("{APPLICATION_TYPE}:{app_public_id}"),
        ));

        for group in groups {
            writes.push(tuple_key(
                ENTITLEMENT_NAMESPACE,
                app_public_id,
                GROUP_REL,
                &format!("{GROUP_TYPE}:{group}#{MEMBER_REL}"),
            ));
        }

        if !writes.is_empty() {
            self.backend
                .write_tuples(tenant_id, &writes, &[])
                .await
                .map_err(map_backend_error)?;
        }

        info!(tenant_id, app_id = app_public_id, "entitlement application seeded");
        Ok(())
    }

    async fn remove_application(&self, tenant_id: &str, app_public_id: &str) -> Result<(), ServiceError> {
        // OpenFGA does not provide a cheap "delete object and all tuples" operation.
        // We list all subjects with relations on this application and delete the
        // corresponding tuples. This is acceptable because the entitlement
        // namespace is small.
        let users = self
            .backend
            .list_users(
                tenant_id,
                ENTITLEMENT_NAMESPACE,
                app_public_id,
                MEMBER_REL,
                &[],
                &QueryOptions::default(),
            )
            .await
            .map_err(map_backend_error)?;
        let admins = self
            .backend
            .list_users(
                tenant_id,
                ENTITLEMENT_NAMESPACE,
                app_public_id,
                ADMIN_REL,
                &[],
                &QueryOptions::default(),
            )
            .await
            .map_err(map_backend_error)?;

        let mut deletes: Vec<RelationTupleKey> = users
            .into_iter()
            .chain(admins)
            .flat_map(|subject| {
                [
                    RelationTupleKey {
                        namespace: ENTITLEMENT_NAMESPACE.to_string(),
                        object: app_public_id.to_string(),
                        relation: MEMBER_REL.to_string(),
                        subject_id: subject.clone(),
                        condition: None,
                        condition_context: None,
                    },
                    RelationTupleKey {
                        namespace: ENTITLEMENT_NAMESPACE.to_string(),
                        object: app_public_id.to_string(),
                        relation: ADMIN_REL.to_string(),
                        subject_id: subject,
                        condition: None,
                        condition_context: None,
                    },
                ]
            })
            .collect();

        // Also remove the group-link tuples.
        deletes.push(RelationTupleKey {
            namespace: ENTITLEMENT_NAMESPACE.to_string(),
            object: app_public_id.to_string(),
            relation: GROUP_REL.to_string(),
            subject_id: format!("{APPLICATION_TYPE}:{app_public_id}#{GROUP_REL}"),
            condition: None,
            condition_context: None,
        });

        // Note: group links (application:app#group @ group:X#member) are not
        // enumerated here because the gateway does not maintain a group registry
        // for entitlements. They become dangling but harmless when the app is
        // retired. See RFC 0001 open question #3.

        // Deduplicate while preserving a deterministic order.
        deletes.sort_by(|a, b| {
            (&a.namespace, &a.object, &a.relation, &a.subject_id)
                .cmp(&(&b.namespace, &b.object, &b.relation, &b.subject_id))
        });
        deletes.dedup();

        self.backend
            .write_tuples(tenant_id, &[], &deletes)
            .await
            .map_err(map_backend_error)?;

        info!(tenant_id, app_id = app_public_id, "entitlement application removed");
        Ok(())
    }

    async fn check(
        &self,
        tenant_id: &str,
        identity_id: &str,
        app_public_id: &str,
        relation: &str,
    ) -> Result<bool, ServiceError> {
        let allowed = self
            .backend
            .check_permission(
                tenant_id,
                ENTITLEMENT_NAMESPACE,
                app_public_id,
                relation,
                identity_id,
                &QueryOptions::default(),
            )
            .await
            .map_err(map_backend_error)?;
        Ok(allowed)
    }

    async fn effective_scope_ceiling(&self, tenant_id: &str, identity_id: &str) -> Vec<String> {
        let is_gateway_admin = match self
            .check(tenant_id, identity_id, GATEWAY_APP_OBJECT, ADMIN_REL)
            .await
        {
            Ok(allowed) => allowed,
            Err(err) => {
                warn!(tenant_id, identity_id, error = %err, "gateway admin entitlement check failed; treating as not admin");
                false
            }
        };
        if is_gateway_admin {
            return admin_scope_ceiling();
        }

        let is_gateway_member = match self
            .check(tenant_id, identity_id, GATEWAY_APP_OBJECT, MEMBER_REL)
            .await
        {
            Ok(allowed) => allowed,
            Err(err) => {
                warn!(tenant_id, identity_id, error = %err, "gateway member entitlement check failed; treating as not member");
                false
            }
        };
        if is_gateway_member {
            return read_scope_ceiling();
        }

        oidc_scope_ceiling()
    }

    async fn grant(
        &self,
        tenant_id: &str,
        identity_id: &str,
        app_public_id: &str,
        level: EntitlementLevel,
    ) -> Result<(), ServiceError> {
        self.ensure_namespace(tenant_id).await?;
        let writes = vec![RelationTupleKey {
            namespace: ENTITLEMENT_NAMESPACE.to_string(),
            object: app_public_id.to_string(),
            relation: level.relation().to_string(),
            subject_id: identity_id.to_string(),
            condition: None,
            condition_context: None,
        }];
        self.backend
            .write_tuples(tenant_id, &writes, &[])
            .await
            .map_err(map_backend_error)?;
        info!(
            target: "sso_gateway::audit",
            tenant_id = tenant_id,
            actor = identity_id,
            application = app_public_id,
            action = "entitlement.grant",
            outcome = "success",
            entitlement_level = ?level,
            "granted application entitlement"
        );
        Ok(())
    }

    async fn revoke(
        &self,
        tenant_id: &str,
        identity_id: &str,
        app_public_id: &str,
        level: EntitlementLevel,
    ) -> Result<(), ServiceError> {
        let deletes = vec![RelationTupleKey {
            namespace: ENTITLEMENT_NAMESPACE.to_string(),
            object: app_public_id.to_string(),
            relation: level.relation().to_string(),
            subject_id: identity_id.to_string(),
            condition: None,
            condition_context: None,
        }];
        self.backend
            .write_tuples(tenant_id, &[], &deletes)
            .await
            .map_err(map_backend_error)?;
        info!(
            target: "sso_gateway::audit",
            tenant_id = tenant_id,
            actor = identity_id,
            application = app_public_id,
            action = "entitlement.revoke",
            outcome = "success",
            entitlement_level = ?level,
            "revoked application entitlement"
        );
        Ok(())
    }

    async fn set_group_membership(
        &self,
        tenant_id: &str,
        group_name: &str,
        identity_id: &str,
        member: bool,
    ) -> Result<(), ServiceError> {
        self.ensure_namespace(tenant_id).await?;
        let key = RelationTupleKey {
            namespace: ENTITLEMENT_NAMESPACE.to_string(),
            object: group_name.to_string(),
            relation: MEMBER_REL.to_string(),
            subject_id: identity_id.to_string(),
            condition: None,
            condition_context: None,
        };
        if member {
            self.backend
                .write_tuples(tenant_id, &[key], &[])
                .await
                .map_err(map_backend_error)?;
        } else {
            self.backend
                .write_tuples(tenant_id, &[], &[key])
                .await
                .map_err(map_backend_error)?;
        }
        info!(
            target: "sso_gateway::audit",
            tenant_id = tenant_id,
            actor = identity_id,
            action = if member { "entitlement.group_member_added" } else { "entitlement.group_member_removed" },
            outcome = "success",
            group = group_name,
            "updated entitlement group membership"
        );
        Ok(())
    }

    async fn remove_all_for_identity(&self, tenant_id: &str, identity_id: &str) -> Result<(), ServiceError> {
        // List every application in the tenant and revoke both member/admin for
        // this identity. Also remove group memberships. This is intentionally
        // exhaustive: a disabled account leaves no lingering tuples.
        let apps = self
            .applications
            .list_by_tenant(tenant_id)
            .await
            .map_err(|e| ServiceError::Database(e.to_string()))?;

        let mut deletes = Vec::new();
        for app in apps {
            for relation in [MEMBER_REL, ADMIN_REL] {
                deletes.push(RelationTupleKey {
                    namespace: ENTITLEMENT_NAMESPACE.to_string(),
                    object: app.public_id.clone(),
                    relation: relation.to_string(),
                    subject_id: identity_id.to_string(),
                    condition: None,
                    condition_context: None,
                });
            }
        }

        // Group memberships: we do not know all groups here, but we can remove
        // tuples where the user is the subject in the group namespace. OpenFGA
        // list_objects/list_users cannot cheaply give us that, so this is a known
        // limitation of the direct-delete path. In practice group removals are
        // handled by the SCIM service calling set_group_membership.
        // TODO: track group membership in Postgres or expose OpenFGA tuple list.
        warn!(
            tenant_id,
            identity_id,
            "remove_all_for_identity may leave orphaned group memberships"
        );

        if !deletes.is_empty() {
            self.backend
                .write_tuples(tenant_id, &[], &deletes)
                .await
                .map_err(map_backend_error)?;
        }

        Ok(())
    }

    async fn mint_claim(
        &self,
        tenant_id: &str,
        identity_id: &str,
        app_public_id: &str,
    ) -> Value {
        let mut levels = Vec::new();
        let is_member = match self
            .check(tenant_id, identity_id, app_public_id, MEMBER_REL)
            .await
        {
            Ok(allowed) => allowed,
            Err(err) => {
                warn!(tenant_id, identity_id, error = %err, "entitlement member check failed; excluding from claim");
                false
            }
        };
        if is_member {
            levels.push("member");
        }
        let is_admin = match self
            .check(tenant_id, identity_id, app_public_id, ADMIN_REL)
            .await
        {
            Ok(allowed) => allowed,
            Err(err) => {
                warn!(tenant_id, identity_id, error = %err, "entitlement admin check failed; excluding from claim");
                false
            }
        };
        if is_admin {
            levels.push("admin");
        }

        if levels.is_empty() {
            return Value::Null;
        }

        serde_json::json!({
            "entitlements": {
                app_public_id: levels
            }
        })
    }
}

fn tuple_key(namespace: &str, object: &str, relation: &str, subject_id: &str) -> RelationTupleKey {
    RelationTupleKey {
        namespace: namespace.to_string(),
        object: object.to_string(),
        relation: relation.to_string(),
        subject_id: subject_id.to_string(),
        condition: None,
        condition_context: None,
    }
}

fn map_backend_error(err: PermissionBackendError) -> ServiceError {
    ServiceError::Internal(format!("entitlement backend error: {err}"))
}

fn entitlement_model() -> Value {
    serde_json::json!({
        "schema_version": "1.1",
        "type_definitions": [
            {"type": "user"},
            {
                "type": "group",
                "relations": {
                    "member": {"this": {}}
                },
                "metadata": {
                    "relations": {
                        "member": {"directly_related_user_types": [{"type": "user"}]}
                    }
                }
            },
            {
                "type": "application",
                "relations": {
                    "group": {"this": {}},
                    "member": {
                        "union": {
                            "child": [
                                {"this": {}},
                                {
                                    "tuple_to_userset": {
                                        "tupleset": {"relation": "group"},
                                        "computed_userset": {"relation": "member"}
                                    }
                                }
                            ]
                        }
                    },
                    "admin": {
                        "union": {
                            "child": [
                                {"this": {}},
                                {
                                    "tuple_to_userset": {
                                        "tupleset": {"relation": "group"},
                                        "computed_userset": {"relation": "member"}
                                    }
                                }
                            ]
                        }
                    }
                },
                "metadata": {
                    "relations": {
                        "group": {"directly_related_user_types": [{"type": "group"}]},
                        "member": {
                            "directly_related_user_types": [{"type": "user"}],
                            "allowed_usersets": [{"type": "group", "relation": "member"}]
                        },
                        "admin": {
                            "directly_related_user_types": [{"type": "user"}],
                            "allowed_usersets": [{"type": "group", "relation": "member"}]
                        }
                    }
                }
            }
        ]
    })
}

fn admin_scope_ceiling() -> Vec<String> {
    vec![
        SCOPE_TENANT_ADMIN.to_string(),
        SCOPE_TENANT_READ.to_string(),
        SCOPE_IDENTITY_ADMIN.to_string(),
        SCOPE_IDENTITY_READ.to_string(),
        SCOPE_SCIM_ADMIN.to_string(),
        SCOPE_SCIM_READ.to_string(),
        SCOPE_PERMISSION_ADMIN.to_string(),
        SCOPE_PERMISSION_READ.to_string(),
        SCOPE_APPLICATION_ADMIN.to_string(),
        SCOPE_APPLICATION_READ.to_string(),
        SCOPE_AGENT_ADMIN.to_string(),
        SCOPE_AGENT_READ.to_string(),
    ]
}

fn read_scope_ceiling() -> Vec<String> {
    vec![
        SCOPE_TENANT_READ.to_string(),
        SCOPE_IDENTITY_READ.to_string(),
        SCOPE_SCIM_READ.to_string(),
        SCOPE_PERMISSION_READ.to_string(),
        SCOPE_APPLICATION_READ.to_string(),
        SCOPE_AGENT_READ.to_string(),
    ]
}

fn oidc_scope_ceiling() -> Vec<String> {
    vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
        "offline_access".to_string(),
    ]
}

pub mod test_helpers {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use serde_json::Value;

    use super::{EntitlementLevel, EntitlementService};
    use sunbeam_g2v::error::ServiceError;

    #[derive(Default, Clone)]
    pub struct NoopEntitlementService;

    #[async_trait]
    impl EntitlementService for NoopEntitlementService {
        async fn ensure_namespace(&self, _tenant_id: &str) -> Result<(), ServiceError> {
            Ok(())
        }

        async fn seed_application(
            &self,
            _tenant_id: &str,
            _app_public_id: &str,
            _groups: &[String],
        ) -> Result<(), ServiceError> {
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
            Ok(true)
        }

        async fn effective_scope_ceiling(
            &self,
            _tenant_id: &str,
            _identity_id: &str,
        ) -> Vec<String> {
            vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
                "offline_access".to_string(),
            ]
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

    pub fn entitlements() -> Arc<dyn EntitlementService> {
        Arc::new(NoopEntitlementService)
    }

    /// Configurable entitlement service for testing enforcement paths.
    #[derive(Default, Clone)]
    #[allow(clippy::type_complexity)]
    pub struct ConfigurableEntitlementService {
        pub member_results: Arc<Mutex<HashMap<(String, String, String), bool>>>,
        pub ceiling: Arc<Mutex<Vec<String>>>,
        pub claim: Arc<Mutex<Value>>,
    }

    impl ConfigurableEntitlementService {
        pub fn allow(&self, tenant_id: &str, identity_id: &str, app_public_id: &str) {
            let mut results = match self.member_results.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            results.insert(
                (tenant_id.to_string(), identity_id.to_string(), app_public_id.to_string()),
                true,
            );
        }

        pub fn deny(&self, tenant_id: &str, identity_id: &str, app_public_id: &str) {
            let mut results = match self.member_results.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            results.insert(
                (tenant_id.to_string(), identity_id.to_string(), app_public_id.to_string()),
                false,
            );
        }

        pub fn set_ceiling(&self, scopes: Vec<String>) {
            let mut ceiling = match self.ceiling.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            *ceiling = scopes;
        }

        pub fn set_claim(&self, claim: Value) {
            let mut current = match self.claim.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            *current = claim;
        }
    }

    #[async_trait]
    impl EntitlementService for ConfigurableEntitlementService {
        async fn ensure_namespace(&self, _tenant_id: &str) -> Result<(), ServiceError> {
            Ok(())
        }

        async fn seed_application(
            &self,
            _tenant_id: &str,
            _app_public_id: &str,
            _groups: &[String],
        ) -> Result<(), ServiceError> {
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
            tenant_id: &str,
            identity_id: &str,
            app_public_id: &str,
            _relation: &str,
        ) -> Result<bool, ServiceError> {
            let key = (tenant_id.to_string(), identity_id.to_string(), app_public_id.to_string());
            let results = match self.member_results.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            Ok(match results.get(&key) {
                Some(v) => *v,
                None => false,
            })
        }

        async fn effective_scope_ceiling(
            &self,
            _tenant_id: &str,
            _identity_id: &str,
        ) -> Vec<String> {
            let ceiling = match self.ceiling.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            ceiling.clone()
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
            let claim = match self.claim.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            claim.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{ApplicationRow, ApplicationStore, DbError};
    use crate::services::permission::{PermissionBackend, PermissionBackendError, QueryOptions};
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    #[allow(clippy::type_complexity)]
    struct MockBackend {
        ensured: Mutex<Vec<(String, String)>>,
        writes: Mutex<Vec<(String, Vec<RelationTupleKey>, Vec<RelationTupleKey>)>>,
        checks: Mutex<Vec<(String, String, String, String, String)>>,
        check_results: Mutex<HashMap<(String, String, String, String), bool>>,
        list_users_results: Mutex<HashMap<(String, String, String, String), Vec<String>>>,
        check_error: Mutex<Option<PermissionBackendError>>,
        write_error: Mutex<Option<PermissionBackendError>>,
        list_users_error: Mutex<Option<PermissionBackendError>>,
    }

    impl MockBackend {
        fn allow(&self, tenant: &str, obj: &str, relation: &str, _subject: &str) {
            self.check_results.lock().unwrap().insert(
                (tenant.to_string(), ENTITLEMENT_NAMESPACE.to_string(), obj.to_string(), relation.to_string()),
                true,
            );
        }

        fn set_users(&self, tenant: &str, obj: &str, relation: &str, users: &[String]) {
            self.list_users_results.lock().unwrap().insert(
                (tenant.to_string(), ENTITLEMENT_NAMESPACE.to_string(), obj.to_string(), relation.to_string()),
                users.to_vec(),
            );
        }

        fn fail_next_check(&self, err: PermissionBackendError) {
            *self.check_error.lock().unwrap() = Some(err);
        }

        fn fail_next_write(&self, err: PermissionBackendError) {
            *self.write_error.lock().unwrap() = Some(err);
        }

        fn fail_next_list_users(&self, err: PermissionBackendError) {
            *self.list_users_error.lock().unwrap() = Some(err);
        }
    }

    #[async_trait]
    impl PermissionBackend for MockBackend {
        async fn check_permission(
            &self,
            tenant_id: &str,
            namespace: &str,
            object: &str,
            relation: &str,
            subject_id: &str,
            _opts: &QueryOptions,
        ) -> Result<bool, PermissionBackendError> {
            if let Some(err) = self.check_error.lock().unwrap().take() {
                return Err(err);
            }
            self.checks.lock().unwrap().push((
                tenant_id.to_string(),
                namespace.to_string(),
                object.to_string(),
                relation.to_string(),
                subject_id.to_string(),
            ));
            let key = (tenant_id.to_string(), namespace.to_string(), object.to_string(), relation.to_string());
            Ok(*self.check_results.lock().unwrap().get(&key).unwrap_or(&false))
        }

        async fn create_relation_tuple(
            &self,
            _tenant_id: &str,
            _namespace: &str,
            _object: &str,
            _relation: &str,
            _subject_id: &str,
        ) -> Result<Value, PermissionBackendError> {
            Ok(Value::Null)
        }

        async fn delete_relation_tuple(
            &self,
            _tenant_id: &str,
            _namespace: &str,
            _object: &str,
            _relation: &str,
            _subject_id: &str,
        ) -> Result<(), PermissionBackendError> {
            Ok(())
        }

        async fn write_tuples(
            &self,
            tenant_id: &str,
            writes: &[RelationTupleKey],
            deletes: &[RelationTupleKey],
        ) -> Result<(), PermissionBackendError> {
            if let Some(err) = self.write_error.lock().unwrap().take() {
                return Err(err);
            }
            self.writes.lock().unwrap().push((
                tenant_id.to_string(),
                writes.to_vec(),
                deletes.to_vec(),
            ));
            Ok(())
        }

        async fn expand(
            &self,
            _tenant_id: &str,
            _namespace: &str,
            _object: &str,
            _relation: &str,
            _opts: &QueryOptions,
        ) -> Result<Value, PermissionBackendError> {
            Ok(Value::Null)
        }

        async fn expand_objects(
            &self,
            _tenant_id: &str,
            _namespace: &str,
            _relation: &str,
            _subject_id: Option<&str>,
            _subject_set_namespace: Option<&str>,
            _subject_set_object: Option<&str>,
            _subject_set_relation: Option<&str>,
            _max_depth: Option<i32>,
            _opts: &QueryOptions,
        ) -> Result<Value, PermissionBackendError> {
            Ok(Value::Null)
        }

        async fn list_users(
            &self,
            tenant_id: &str,
            namespace: &str,
            object: &str,
            relation: &str,
            _user_type_filters: &[String],
            _opts: &QueryOptions,
        ) -> Result<Vec<String>, PermissionBackendError> {
            if let Some(err) = self.list_users_error.lock().unwrap().take() {
                return Err(err);
            }
            let key = (tenant_id.to_string(), namespace.to_string(), object.to_string(), relation.to_string());
            Ok(self.list_users_results.lock().unwrap().get(&key).cloned().unwrap_or_default())
        }

        async fn ensure_namespace(
            &self,
            _tenant_id: &str,
            _namespace: &str,
            _relations: &[String],
        ) -> Result<(), PermissionBackendError> {
            Ok(())
        }

        async fn ensure_model(
            &self,
            tenant_id: &str,
            namespace: &str,
            _model: &Value,
        ) -> Result<(), PermissionBackendError> {
            self.ensured.lock().unwrap().push((tenant_id.to_string(), namespace.to_string()));
            Ok(())
        }

        async fn delete_namespace(
            &self,
            _tenant_id: &str,
            _namespace: &str,
        ) -> Result<(), PermissionBackendError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockApplicationStore {
        apps: Mutex<Vec<ApplicationRow>>,
        list_error: Mutex<Option<DbError>>,
    }

    impl MockApplicationStore {
        fn with_apps(apps: &[ApplicationRow]) -> Self {
            Self {
                apps: Mutex::new(apps.to_vec()),
                list_error: Mutex::new(None),
            }
        }

        fn fail_next_list(&self, err: DbError) {
            *self.list_error.lock().unwrap() = Some(err);
        }
    }

    #[async_trait]
    impl ApplicationStore for MockApplicationStore {
        async fn create(
            &self,
            _tenant_id: &str,
            _public_id: &str,
            _cross_tenant: bool,
        ) -> Result<ApplicationRow, DbError> {
            unimplemented!()
        }

        async fn get(
            &self,
            _tenant_id: &str,
            _public_id: &str,
        ) -> Result<ApplicationRow, DbError> {
            unimplemented!()
        }

        async fn get_by_public_id(&self, _public_id: &str) -> Result<ApplicationRow, DbError> {
            unimplemented!()
        }

        async fn list_by_tenant(&self, _tenant_id: &str) -> Result<Vec<ApplicationRow>, DbError> {
            if let Some(err) = self.list_error.lock().unwrap().take() {
                return Err(err);
            }
            Ok(self.apps.lock().unwrap().clone())
        }

        async fn set_cross_tenant(
            &self,
            _tenant_id: &str,
            _public_id: &str,
            _cross_tenant: bool,
        ) -> Result<ApplicationRow, DbError> {
            unimplemented!()
        }

        async fn delete(&self, _tenant_id: &str, _public_id: &str) -> Result<(), DbError> {
            unimplemented!()
        }
    }

    fn service() -> (EntitlementServiceImpl, Arc<MockBackend>, Arc<MockApplicationStore>) {
        let backend = Arc::new(MockBackend::default());
        let apps = Arc::new(MockApplicationStore::default());
        let svc = EntitlementServiceImpl::new(backend.clone(), apps.clone());
        (svc, backend, apps)
    }

    #[test]
    fn entitlement_model_is_valid_json() {
        let model = entitlement_model();
        assert!(model.get("schema_version").is_some());
        assert!(model.get("type_definitions").is_some());
    }

    #[test]
    fn scope_ceilings_are_stable() {
        assert_eq!(admin_scope_ceiling().len(), 12);
        assert_eq!(read_scope_ceiling().len(), 6);
        assert_eq!(oidc_scope_ceiling().len(), 4);
    }

    #[tokio::test]
    async fn ensure_namespace_calls_backend() {
        let (svc, backend, _) = service();
        svc.ensure_namespace("tenant-1").await.unwrap();
        let ensured = backend.ensured.lock().unwrap();
        assert_eq!(ensured.as_slice(), &[("tenant-1".to_string(), ENTITLEMENT_NAMESPACE.to_string())]);
    }

    #[tokio::test]
    async fn seed_application_writes_group_links() {
        let (svc, backend, _) = service();
        svc.seed_application("tenant-1", "app-1", &["employees".to_string()])
            .await
            .unwrap();
        let writes = backend.writes.lock().unwrap();
        assert_eq!(writes.len(), 1);
        let (_, writes, _) = &writes[0];
        assert_eq!(writes.len(), 2);
        assert_eq!(writes[0].namespace, ENTITLEMENT_NAMESPACE);
        assert_eq!(writes[0].object, "app-1");
        assert_eq!(writes[0].relation, GROUP_REL);
        assert_eq!(writes[1].namespace, ENTITLEMENT_NAMESPACE);
        assert_eq!(writes[1].object, "app-1");
        assert_eq!(writes[1].relation, GROUP_REL);
    }

    #[tokio::test]
    async fn check_resolves_allowed() {
        let (svc, backend, _) = service();
        backend.allow("tenant-1", "app-1", MEMBER_REL, "user-1");
        assert!(svc.check("tenant-1", "user-1", "app-1", MEMBER_REL).await.unwrap());
    }

    #[tokio::test]
    async fn effective_scope_ceiling_returns_admin_scopes() {
        let (svc, backend, _) = service();
        backend.allow("tenant-1", GATEWAY_APP_OBJECT, ADMIN_REL, "user-1");
        let ceiling = svc.effective_scope_ceiling("tenant-1", "user-1").await;
        assert!(ceiling.contains(&SCOPE_APPLICATION_ADMIN.to_string()));
        assert!(ceiling.contains(&SCOPE_APPLICATION_READ.to_string()));
    }

    #[tokio::test]
    async fn effective_scope_ceiling_returns_read_scopes() {
        let (svc, backend, _) = service();
        backend.allow("tenant-1", GATEWAY_APP_OBJECT, MEMBER_REL, "user-1");
        let ceiling = svc.effective_scope_ceiling("tenant-1", "user-1").await;
        assert!(!ceiling.contains(&SCOPE_APPLICATION_ADMIN.to_string()));
        assert!(ceiling.contains(&SCOPE_APPLICATION_READ.to_string()));
    }

    #[tokio::test]
    async fn effective_scope_ceiling_returns_oidc_only() {
        let (svc, _, _) = service();
        let ceiling = svc.effective_scope_ceiling("tenant-1", "user-1").await;
        assert_eq!(ceiling, oidc_scope_ceiling());
    }

    #[tokio::test]
    async fn grant_writes_member_tuple() {
        let (svc, backend, _) = service();
        svc.grant("tenant-1", "user-1", "app-1", EntitlementLevel::Member)
            .await
            .unwrap();
        let writes = backend.writes.lock().unwrap();
        assert_eq!(writes.len(), 1);
        let (_, grant_writes, _) = &writes[0];
        assert_eq!(grant_writes.len(), 1);
        assert_eq!(grant_writes[0].relation, MEMBER_REL);
        assert_eq!(grant_writes[0].subject_id, "user-1");
    }

    #[tokio::test]
    async fn revoke_deletes_tuple() {
        let (svc, backend, _) = service();
        svc.revoke("tenant-1", "user-1", "app-1", EntitlementLevel::Admin)
            .await
            .unwrap();
        let writes = backend.writes.lock().unwrap();
        let (_, _, deletes) = &writes[0];
        assert_eq!(deletes.len(), 1);
        assert_eq!(deletes[0].relation, ADMIN_REL);
    }

    #[tokio::test]
    async fn set_group_membership_writes_and_deletes() {
        let (svc, backend, _) = service();
        svc.set_group_membership("tenant-1", "employees", "user-1", true)
            .await
            .unwrap();
        svc.set_group_membership("tenant-1", "employees", "user-1", false)
            .await
            .unwrap();
        let writes = backend.writes.lock().unwrap();
        assert_eq!(writes.len(), 2); // ensure + add, then delete
        let (_, add_writes, _) = &writes[0];
        assert_eq!(add_writes[0].relation, MEMBER_REL);
        assert_eq!(add_writes[0].object, "employees");
        let (_, _, remove_deletes) = &writes[1];
        assert_eq!(remove_deletes[0].relation, MEMBER_REL);
    }

    #[tokio::test]
    async fn mint_claim_returns_levels() {
        let (svc, backend, _) = service();
        backend.allow("tenant-1", "app-1", MEMBER_REL, "user-1");
        backend.allow("tenant-1", "app-1", ADMIN_REL, "user-1");
        let claim = svc.mint_claim("tenant-1", "user-1", "app-1").await;
        let obj = claim.as_object().unwrap();
        let entitlements = obj.get("entitlements").unwrap().as_object().unwrap();
        let app = entitlements.get("app-1").unwrap().as_array().unwrap();
        assert!(app.iter().any(|v| v.as_str() == Some("member")));
        assert!(app.iter().any(|v| v.as_str() == Some("admin")));
    }

    #[tokio::test]
    async fn mint_claim_returns_null_when_no_entitlement() {
        let (svc, _, _) = service();
        let claim = svc.mint_claim("tenant-1", "user-1", "app-1").await;
        assert!(claim.is_null());
    }

    #[tokio::test]
    async fn remove_application_deletes_member_admin_and_group_tuples() {
        let (svc, backend, _) = service();
        backend.set_users("tenant-1", "app-1", MEMBER_REL, &["user-1".to_string(), "user-2".to_string()]);
        backend.set_users("tenant-1", "app-1", ADMIN_REL, &["user-3".to_string()]);
        svc.remove_application("tenant-1", "app-1").await.unwrap();

        let writes = backend.writes.lock().unwrap();
        assert_eq!(writes.len(), 1);
        let (_, _, deletes) = &writes[0];
        // Two deletes per user (member + admin) plus the self group-link tuple.
        assert_eq!(deletes.len(), 7);
        for user in ["user-1", "user-2"] {
            assert!(deletes.iter().any(|k| {
                k.relation == MEMBER_REL && k.subject_id == user && k.namespace == ENTITLEMENT_NAMESPACE
            }));
            assert!(deletes.iter().any(|k| {
                k.relation == ADMIN_REL && k.subject_id == user && k.namespace == ENTITLEMENT_NAMESPACE
            }));
        }
        assert!(deletes.iter().any(|k| {
            k.relation == MEMBER_REL && k.subject_id == "user-3" && k.namespace == ENTITLEMENT_NAMESPACE
        }));
        assert!(deletes.iter().any(|k| {
            k.relation == ADMIN_REL && k.subject_id == "user-3" && k.namespace == ENTITLEMENT_NAMESPACE
        }));
        assert!(deletes.iter().any(|k| {
            k.relation == GROUP_REL && k.subject_id == format!("{APPLICATION_TYPE}:app-1#{GROUP_REL}")
        }));
    }

    #[tokio::test]
    async fn remove_application_propagates_list_users_error() {
        let (svc, backend, _) = service();
        backend.fail_next_list_users(PermissionBackendError::Ory {
            status: 500,
            message: "keto down".into(),
        });
        let err = svc.remove_application("tenant-1", "app-1").await.unwrap_err();
        assert!(matches!(err, ServiceError::Internal(_)));
    }

    #[tokio::test]
    async fn remove_all_for_identity_deletes_tuples_for_all_apps() {
        let apps = Arc::new(MockApplicationStore::with_apps(&[
            ApplicationRow {
                tenant_id: "tenant-1".into(),
                public_id: "app-1".into(),
                cross_tenant: false,
                created_at: time::OffsetDateTime::now_utc(),
                updated_at: time::OffsetDateTime::now_utc(),
            },
            ApplicationRow {
                tenant_id: "tenant-1".into(),
                public_id: "app-2".into(),
                cross_tenant: false,
                created_at: time::OffsetDateTime::now_utc(),
                updated_at: time::OffsetDateTime::now_utc(),
            },
        ]));
        let backend = Arc::new(MockBackend::default());
        let svc = EntitlementServiceImpl::new(backend.clone(), apps);
        svc.remove_all_for_identity("tenant-1", "user-1").await.unwrap();

        let writes = backend.writes.lock().unwrap();
        assert_eq!(writes.len(), 1);
        let (_, _, deletes) = &writes[0];
        assert_eq!(deletes.len(), 4);
        for app in ["app-1", "app-2"] {
            assert!(deletes.iter().any(|k| {
                k.object == app && k.relation == MEMBER_REL && k.subject_id == "user-1"
            }));
            assert!(deletes.iter().any(|k| {
                k.object == app && k.relation == ADMIN_REL && k.subject_id == "user-1"
            }));
        }
    }

    #[tokio::test]
    async fn remove_all_for_identity_propagates_store_error() {
        let apps = Arc::new(MockApplicationStore::default());
        apps.fail_next_list(DbError::TenantNotFound);
        let backend = Arc::new(MockBackend::default());
        let svc = EntitlementServiceImpl::new(backend, apps);
        let err = svc.remove_all_for_identity("tenant-1", "user-1").await.unwrap_err();
        assert!(matches!(err, ServiceError::Database(_)));
    }

    #[tokio::test]
    async fn check_propagates_backend_error() {
        let (svc, backend, _) = service();
        backend.fail_next_check(PermissionBackendError::Ory {
            status: 500,
            message: "keto down".into(),
        });
        let err = svc.check("tenant-1", "user-1", "app-1", MEMBER_REL).await.unwrap_err();
        assert!(matches!(err, ServiceError::Internal(_)));
    }

    #[tokio::test]
    async fn grant_propagates_backend_write_error() {
        let (svc, backend, _) = service();
        backend.fail_next_write(PermissionBackendError::Ory {
            status: 500,
            message: "keto down".into(),
        });
        let err = svc
            .grant("tenant-1", "user-1", "app-1", EntitlementLevel::Member)
            .await
            .unwrap_err();
        assert!(matches!(err, ServiceError::Internal(_)));
    }
}
