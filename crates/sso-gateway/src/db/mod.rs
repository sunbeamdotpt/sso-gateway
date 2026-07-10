//! Database access layer for the SSO gateway.
//!
//! The module is split into per-domain submodules. Each domain exposes a row
//! type, an `async-trait` store trait, and a PostgreSQL implementation named
//! `Pg<Domain>Store`. For backward compatibility with the previous monolithic
//! `db.rs`, the old `*Repo` names are re-exported as aliases to the concrete
//! PostgreSQL stores.

mod connection;
mod crypto;
mod domain;
mod error;
mod id_mapping;
mod identity_schema;
mod local_auth;
mod login_state;
mod permission;
mod pool;
mod saml_identity_mapping;
mod saml_idp_key;
mod saml_nameid_mapping;
mod saml_provider;
mod saml_replay_cache;
mod saml_request;
mod saml_sp_client;
mod scim_group;
mod session_store;
mod tenant;
mod tenant_membership;
mod token_cache;
mod transient_token;

pub use connection::{
    ConnectionType, PgTenantConnectionStore, TenantConnectionRow, TenantConnectionStore,
};
pub use domain::{PgTenantDomainStore, TenantDomainRow, TenantDomainStore};
pub use error::DbError;
pub use id_mapping::{IdMappingRow, IdMappingStore, PgIdMappingStore};
pub use identity_schema::{IdentitySchemaRow, IdentitySchemaStore, PgIdentitySchemaStore};
pub use local_auth::{
    LocalAuthMethod, PgTenantLocalAuthStore, TenantLocalAuthRow, TenantLocalAuthStore,
};
pub use login_state::{LoginStateRow, LoginStateStore, PgLoginStateStore};
pub use permission::{PermissionTupleRow, PermissionTupleStore, PgPermissionTupleStore};
pub use pool::{DbPool, bootstrap_system_tenant, create_pool};
pub use saml_identity_mapping::{
    PgSamlIdentityMappingStore, SamlIdentityMappingRow, SamlIdentityMappingStore,
};
pub use saml_idp_key::{PgSamlIdpKeyStore, SamlIdpKeyRow, SamlIdpKeyStore};
pub use saml_nameid_mapping::{
    PgSamlNameIdMappingStore, SamlNameIdMappingRow, SamlNameIdMappingStore,
    compute_pairwise_name_id,
};
pub use saml_provider::{PgSamlProviderStore, SamlProviderRow, SamlProviderStore};
pub use saml_replay_cache::{
    GamlastanReplayAdapter, ReplayCache as SamlReplayCacheTrait, SamlReplayCache,
};
pub use saml_request::{PgSamlRequestStore, SamlRequestRow, SamlRequestStore};
pub use saml_sp_client::{PgSamlSpClientStore, SamlSpClientRow, SamlSpClientStore};
pub use scim_group::{PgScimGroupStore, ScimGroupRow, ScimGroupStore};
pub use session_store::{PgSessionStore, SessionStore};
pub use tenant::{PgTenantStore, TenantRow, TenantStore};
pub use tenant_membership::{
    PgTenantMembershipStore, TenantMembershipRow, TenantMembershipStore,
};
pub use token_cache::{PgTokenIntrospectionCache, TokenIntrospectionCache, TokenIntrospectionRow};
pub use transient_token::{
    PgTransientTokenStore, TOKEN_TYPE_CONSENT_CHALLENGE, TOKEN_TYPE_FLOW,
    TOKEN_TYPE_LOGIN_CHALLENGE, TOKEN_TYPE_LOGOUT_CHALLENGE, TOKEN_TYPE_LOGOUT_TOKEN,
    TOKEN_TYPE_RECOVERY_TOKEN, TOKEN_TYPE_SESSION, TOKEN_TYPE_VERIFICATION_TOKEN,
    TransientTokenRow, TransientTokenStore,
};

// Backward-compatible concrete repo aliases.
pub use connection::PgTenantConnectionStore as TenantConnectionRepo;
pub use domain::PgTenantDomainStore as TenantDomainRepo;
pub use id_mapping::PgIdMappingStore as IdMappingRepo;
pub use identity_schema::PgIdentitySchemaStore as IdentitySchemaRepo;
pub use local_auth::PgTenantLocalAuthStore as TenantLocalAuthRepo;
pub use login_state::PgLoginStateStore as LoginStateRepo;
pub use permission::PgPermissionTupleStore as PermissionTupleRepo;
pub use saml_identity_mapping::PgSamlIdentityMappingStore as SamlIdentityMappingRepo;
pub use saml_idp_key::PgSamlIdpKeyStore as SamlIdpKeyRepo;
pub use saml_nameid_mapping::PgSamlNameIdMappingStore as SamlNameIdMappingRepo;
pub use saml_provider::PgSamlProviderStore as SamlProviderRepo;
pub use saml_request::PgSamlRequestStore as SamlRequestRepo;
pub use saml_sp_client::PgSamlSpClientStore as SamlSpClientRepo;
pub use scim_group::PgScimGroupStore as ScimGroupRepo;
pub use tenant::PgTenantStore as TenantRepo;
pub use tenant_membership::PgTenantMembershipStore as TenantMembershipRepo;
pub use transient_token::PgTransientTokenStore as TransientTokenRepo;
