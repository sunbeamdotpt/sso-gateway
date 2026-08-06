//! Shared resolution of an OAuth2 client's entitlement/ownership state
//! (SSO-039 consent-gated first use).
//!
//! The login gate (`identity_self_service`) and the consent gate
//! (`oauth2_consent`) must classify a Hydra client identically, so the
//! resolution lives here exactly once:
//!
//! - **Local**: the client resolves in the caller's tenant and has an
//!   `applications` row. The row's `registration_source` decides first-use
//!   eligibility (`dcr` eligible, `admin` never).
//! - **CrossTenantOwned**: no mapping in the caller's tenant, but the client
//!   is mapped in another tenant that holds its `applications` row. Ownership
//!   is first-consent-wins and permanent: gates fail closed — unless the
//!   row's `cross_tenant` flag is set, in which case subjects from other
//!   tenants may hold per-user entitlements on the app, checked in the OWNER
//!   tenant's entitlement store against the foreign user's (globally unique)
//!   public ULID.
//! - **Provisional**: mapped (somewhere) but with no `applications` row
//!   anywhere — a post-deploy DCR registration nobody has consented to yet.
//!   Eligible; the first consenting user's tenant claims it.
//! - **Unmapped**: no mapping anywhere (legacy clients, heal paths). Gates
//!   keep the historical pass-through; a hard deny here is a documented
//!   follow-up.

use crate::db::{ApplicationStore, DbError, IdMappingStore, REGISTRATION_SOURCE_DCR};

const BACKEND_HYDRA: &str = "hydra";

/// Ownership/registration state of an OAuth2 client relative to a tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientEntitlement {
    /// Resolved in the caller's tenant with an `applications` row.
    Local {
        public_id: String,
        /// `applications.registration_source` (`admin` or `dcr`).
        source: String,
    },
    /// Owned by another tenant (its `applications` row exists there).
    /// `cross_tenant` is the row's flag: subjects from other tenants may hold
    /// per-user entitlements on this app, checked in the OWNER tenant's
    /// entitlement store.
    CrossTenantOwned {
        public_id: String,
        owner_tenant: String,
        cross_tenant: bool,
    },
    /// Mapped but with no `applications` row anywhere — a DCR registration
    /// nobody has consented to yet. `owner_tenant` is the tenant currently
    /// holding the mapping; the first consenting user's tenant claims the
    /// client by re-homing the mapping.
    Provisional {
        public_id: String,
        owner_tenant: String,
    },
    /// No mapping anywhere (legacy/heal paths).
    Unmapped,
}

impl ClientEntitlement {
    /// The gateway public id of the client, when it resolved to one.
    pub fn public_id(&self) -> Option<&str> {
        match self {
            ClientEntitlement::Local { public_id, .. }
            | ClientEntitlement::CrossTenantOwned { public_id, .. }
            | ClientEntitlement::Provisional { public_id, .. } => Some(public_id),
            ClientEntitlement::Unmapped => None,
        }
    }

    /// Whether an unentitled user may be offered first-use consent: DCR-registered
    /// (row marked `dcr`, or no row at all) and not owned by another tenant.
    pub fn is_first_use_eligible(&self) -> bool {
        match self {
            ClientEntitlement::Local { source, .. } => source == REGISTRATION_SOURCE_DCR,
            ClientEntitlement::Provisional { .. } => true,
            ClientEntitlement::CrossTenantOwned { .. } | ClientEntitlement::Unmapped => false,
        }
    }
}

/// Resolve a Hydra client to its entitlement/ownership state for `tenant_id`.
///
/// Mapping/application lookup errors other than not-found propagate as
/// `DbError`; callers decide whether to fail open (login gate, historical
/// behavior) or closed.
pub async fn resolve_client_entitlement(
    mappings: &dyn IdMappingStore,
    applications: &dyn ApplicationStore,
    tenant_id: &str,
    ory_client_id: &str,
) -> Result<ClientEntitlement, DbError> {
    match mappings
        .get_public_id(tenant_id, BACKEND_HYDRA, ory_client_id)
        .await
    {
        Ok(public_id) => classify_owned(applications, tenant_id, tenant_id, public_id).await,
        Err(DbError::MappingNotFound) => {
            let Some(owner_tenant) = mappings
                .get_tenant_id_by_ory_id(BACKEND_HYDRA, ory_client_id)
                .await?
            else {
                return Ok(ClientEntitlement::Unmapped);
            };
            let public_id = match mappings
                .get_public_id_by_ory_id(BACKEND_HYDRA, ory_client_id)
                .await
            {
                Ok(public_id) => public_id,
                // Inconsistent store state (owner without a public id); treat
                // as unmapped so the gates keep the historical pass-through.
                Err(DbError::MappingNotFound) => return Ok(ClientEntitlement::Unmapped),
                Err(err) => return Err(err),
            };
            classify_owned(applications, tenant_id, &owner_tenant, public_id).await
        }
        Err(err) => Err(err),
    }
}

/// Classify a resolved client by its `applications` row. `owner_tenant` is
/// the tenant holding the client's mapping; when it differs from the
/// caller's `tenant_id`, an existing row means cross-tenant ownership.
async fn classify_owned(
    applications: &dyn ApplicationStore,
    tenant_id: &str,
    owner_tenant: &str,
    public_id: String,
) -> Result<ClientEntitlement, DbError> {
    // `public_id` is globally unique, so the row (when it exists) is the
    // owner's row regardless of which tenant column we filter by.
    match applications.get_by_public_id(&public_id).await {
        Ok(row) => {
            if row.tenant_id == tenant_id {
                Ok(ClientEntitlement::Local {
                    public_id,
                    source: row.registration_source,
                })
            } else {
                Ok(ClientEntitlement::CrossTenantOwned {
                    public_id,
                    owner_tenant: row.tenant_id,
                    cross_tenant: row.cross_tenant,
                })
            }
        }
        Err(DbError::ApplicationNotFound) => Ok(ClientEntitlement::Provisional {
            public_id,
            owner_tenant: owner_tenant.to_string(),
        }),
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{MemoryApplicationStore, MemoryIdMappingStore, REGISTRATION_SOURCE_ADMIN};

    fn stores() -> (MemoryIdMappingStore, MemoryApplicationStore) {
        (
            MemoryIdMappingStore::default(),
            MemoryApplicationStore::default(),
        )
    }

    #[tokio::test]
    async fn local_admin_row_resolves_with_source() {
        let (mappings, applications) = stores();
        mappings
            .create("tenant-1", BACKEND_HYDRA, "pub-1", "ory-1")
            .await
            .unwrap();
        applications
            .create("tenant-1", "pub-1", false, REGISTRATION_SOURCE_ADMIN)
            .await
            .unwrap();

        let resolved = resolve_client_entitlement(&mappings, &applications, "tenant-1", "ory-1")
            .await
            .unwrap();
        assert_eq!(
            resolved,
            ClientEntitlement::Local {
                public_id: "pub-1".to_string(),
                source: REGISTRATION_SOURCE_ADMIN.to_string(),
            }
        );
        assert!(!resolved.is_first_use_eligible());
    }

    #[tokio::test]
    async fn local_dcr_row_is_first_use_eligible() {
        let (mappings, applications) = stores();
        mappings
            .create("tenant-1", BACKEND_HYDRA, "pub-1", "ory-1")
            .await
            .unwrap();
        applications
            .create("tenant-1", "pub-1", false, REGISTRATION_SOURCE_DCR)
            .await
            .unwrap();

        let resolved = resolve_client_entitlement(&mappings, &applications, "tenant-1", "ory-1")
            .await
            .unwrap();
        assert!(resolved.is_first_use_eligible());
    }

    #[tokio::test]
    async fn local_mapping_without_row_is_provisional() {
        let (mappings, applications) = stores();
        mappings
            .create("tenant-1", BACKEND_HYDRA, "pub-1", "ory-1")
            .await
            .unwrap();

        let resolved = resolve_client_entitlement(&mappings, &applications, "tenant-1", "ory-1")
            .await
            .unwrap();
        assert_eq!(
            resolved,
            ClientEntitlement::Provisional {
                public_id: "pub-1".to_string(),
                owner_tenant: "tenant-1".to_string(),
            }
        );
        assert!(resolved.is_first_use_eligible());
    }

    #[tokio::test]
    async fn mapping_in_other_tenant_with_row_is_cross_tenant_owned() {
        let (mappings, applications) = stores();
        mappings
            .create("tenant-a", BACKEND_HYDRA, "pub-1", "ory-1")
            .await
            .unwrap();
        applications
            .create("tenant-a", "pub-1", false, REGISTRATION_SOURCE_DCR)
            .await
            .unwrap();

        let resolved = resolve_client_entitlement(&mappings, &applications, "tenant-b", "ory-1")
            .await
            .unwrap();
        assert_eq!(
            resolved,
            ClientEntitlement::CrossTenantOwned {
                public_id: "pub-1".to_string(),
                owner_tenant: "tenant-a".to_string(),
                cross_tenant: false,
            }
        );
        assert!(!resolved.is_first_use_eligible());
    }

    #[tokio::test]
    async fn cross_tenant_owned_carries_the_rows_cross_tenant_flag() {
        let (mappings, applications) = stores();
        mappings
            .create("tenant-a", BACKEND_HYDRA, "pub-1", "ory-1")
            .await
            .unwrap();
        applications
            .create("tenant-a", "pub-1", true, REGISTRATION_SOURCE_ADMIN)
            .await
            .unwrap();

        let resolved = resolve_client_entitlement(&mappings, &applications, "tenant-b", "ory-1")
            .await
            .unwrap();
        assert_eq!(
            resolved,
            ClientEntitlement::CrossTenantOwned {
                public_id: "pub-1".to_string(),
                owner_tenant: "tenant-a".to_string(),
                cross_tenant: true,
            }
        );
        // A flagged app is still owned: never first-use eligible.
        assert!(!resolved.is_first_use_eligible());
    }

    #[tokio::test]
    async fn mapping_in_other_tenant_without_row_is_provisional() {
        let (mappings, applications) = stores();
        mappings
            .create("tenant-a", BACKEND_HYDRA, "pub-1", "ory-1")
            .await
            .unwrap();

        let resolved = resolve_client_entitlement(&mappings, &applications, "tenant-b", "ory-1")
            .await
            .unwrap();
        assert_eq!(
            resolved,
            ClientEntitlement::Provisional {
                public_id: "pub-1".to_string(),
                owner_tenant: "tenant-a".to_string(),
            }
        );
        assert!(resolved.is_first_use_eligible());
    }

    #[tokio::test]
    async fn unmapped_client_resolves_unmapped() {
        let (mappings, applications) = stores();
        let resolved = resolve_client_entitlement(&mappings, &applications, "tenant-1", "ory-1")
            .await
            .unwrap();
        assert_eq!(resolved, ClientEntitlement::Unmapped);
        assert!(!resolved.is_first_use_eligible());
        assert_eq!(resolved.public_id(), None);
    }
}
