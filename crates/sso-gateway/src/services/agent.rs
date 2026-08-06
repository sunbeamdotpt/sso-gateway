//! Agent identity and delegation service.
//!
//! Agents are gateway-owned non-human identities: each agent is a row in
//! `agents` plus a Hydra OAuth2 client (client_credentials grant) whose client
//! id is the agent's public ULID. Agents never touch Kratos.
//!
//! On-behalf-of access uses pre-authorized grants: a user creates an
//! `AgentDelegation`, the agent mints short-lived opaque act-tokens against
//! it, and every use of an act-token re-validates the grant through the
//! [`AgentTokenAuthority`] (instant revocation, cached introspection).

use std::sync::Arc;

use base64::Engine;
use buffa::MessageField;
use buffa_types::google::protobuf::{Empty, Timestamp};
use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult};
use serde_json::Value;
use sunbeam_g2v::error::ServiceError;
use tracing::{instrument, warn};

use crate::{
    agent_tokens::{AgentTokenAuthority, AgentTokenResolver},
    auth::{
        AuthContext, KNOWN_SCOPES, SCOPE_AGENT_ACT, SCOPE_AGENT_ADMIN, SCOPE_AGENT_READ,
        SubjectType, require_scope, require_subject_type,
    },
    db::{
        AGENT_STATUS_ACTIVE, AGENT_STATUS_DISABLED, AgentDelegationRow, AgentDelegationStore,
        AgentRow, AgentStore, DbError, IdMappingStore, TenantMembershipStore,
    },
    middleware::TenantId,
    proto::iam::v1::{
        Agent, AgentActToken, AgentActTokenIntrospection, AgentDelegation, AgentSecret,
        AgentService, CreateAgentDelegationRequest, CreateAgentRequest, DeleteAgentRequest,
        GetAgentRequest, IntrospectAgentActTokenRequest, ListAgentDelegationsRequest,
        ListAgentDelegationsResponse, ListAgentsRequest, ListAgentsResponse,
        MintAgentActTokenRequest, PageResponse, RevokeAgentDelegationRequest,
        RotateAgentSecretRequest, UpdateAgentRequest,
    },
    services::client_credential::{ClientCredentialHydra, map_ory_error},
};

const BACKEND_HYDRA: &str = "hydra";
const GRANT_TYPE_CLIENT_CREDENTIALS: &str = "client_credentials";
const MEMBERSHIP_STATE_ACTIVE: &str = "active";

const DEFAULT_PAGE_SIZE: u32 = 50;
const MAX_PAGE_SIZE: u32 = 200;

/// Delegation scopes are opaque to the gateway (downstream services interpret
/// them), so validation is limited to shape, count, and length sanity bounds.
const MAX_DELEGATION_SCOPES: usize = 64;
const MAX_SCOPE_LEN: usize = 128;

#[derive(Clone)]
pub struct AgentServiceImpl {
    hydra: Arc<dyn ClientCredentialHydra>,
    mappings: Arc<dyn IdMappingStore>,
    agents: Arc<dyn AgentStore>,
    delegations: Arc<dyn AgentDelegationStore>,
    memberships: Arc<dyn TenantMembershipStore>,
    authority: Arc<AgentTokenAuthority>,
}

impl AgentServiceImpl {
    pub fn new(
        hydra: Arc<dyn ClientCredentialHydra>,
        mappings: Arc<dyn IdMappingStore>,
        agents: Arc<dyn AgentStore>,
        delegations: Arc<dyn AgentDelegationStore>,
        memberships: Arc<dyn TenantMembershipStore>,
        authority: Arc<AgentTokenAuthority>,
    ) -> Self {
        Self {
            hydra,
            mappings,
            agents,
            delegations,
            memberships,
            authority,
        }
    }

    /// The delegating user must be an active member of the tenant.
    async fn require_active_member(
        &self,
        tenant_id: &str,
        identity_id: &str,
    ) -> Result<(), ServiceError> {
        match self.memberships.get(tenant_id, identity_id).await {
            Ok(row) if row.state == MEMBERSHIP_STATE_ACTIVE => Ok(()),
            Ok(_) => Err(ServiceError::PermissionDenied(
                "identity is not an active tenant member".into(),
            )),
            Err(DbError::MembershipNotFound) => Err(ServiceError::PermissionDenied(
                "identity is not a tenant member".into(),
            )),
            Err(err) => Err(err.into()),
        }
    }
}

#[allow(refining_impl_trait)]
impl AgentService for AgentServiceImpl {
    #[instrument(skip(self))]
    async fn create_agent(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateAgentRequest>,
    ) -> ServiceResult<Agent> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope(&ctx, SCOPE_AGENT_ADMIN)?;
        let req = request.to_owned_message();

        if req.name.is_empty() {
            return Err(ServiceError::InvalidArgument("name is required".into()).into());
        }
        validate_client_scopes(&req.scope)?;

        // The owner is recorded only for human callers; an agent creating
        // another agent leaves the agent tenant-owned.
        let auth = ctx.extensions().get::<AuthContext>();
        let owner = auth
            .filter(|a| a.subject_type == SubjectType::User)
            .map(|a| a.subject.as_str());

        let agent = self.agents.create(&tenant_id, owner, &req.name).await?;

        let payload = serde_json::json!({
            "client_id": agent.id,
            "client_name": req.name,
            "grant_types": [GRANT_TYPE_CLIENT_CREDENTIALS],
            "scope": req.scope.join(" "),
            "token_endpoint_auth_method": "client_secret_basic",
        });
        let created = match self.hydra.create_oauth2_client(payload).await {
            Ok(created) => created,
            Err(err) => {
                if let Err(e) = self.agents.delete(&tenant_id, &agent.id).await {
                    warn!(agent_id = %agent.id, "compensating agent delete failed: {}", e);
                }
                return Err(map_ory_error(err).into());
            }
        };
        let ory_id = match created["client_id"].as_str() {
            Some(id) => id.to_string(),
            None => agent.id.clone(),
        };
        let client_secret = match created["client_secret"].as_str() {
            Some(secret) => secret.to_string(),
            None => String::new(),
        };

        if let Err(err) = self
            .mappings
            .create(&tenant_id, BACKEND_HYDRA, &agent.id, &ory_id)
            .await
        {
            if let Err(e) = self.hydra.delete_oauth2_client(&ory_id).await {
                warn!(agent_id = %agent.id, "compensating hydra delete failed: {}", e);
            }
            if let Err(e) = self.agents.delete(&tenant_id, &agent.id).await {
                warn!(agent_id = %agent.id, "compensating agent delete failed: {}", e);
            }
            return Err(err.into());
        }

        let mut proto = agent_to_proto(&agent);
        proto.client_secret = client_secret;
        Ok(Response::new(proto))
    }

    #[instrument(skip(self))]
    async fn get_agent(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetAgentRequest>,
    ) -> ServiceResult<Agent> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope_any(&ctx, &[SCOPE_AGENT_READ, SCOPE_AGENT_ADMIN])?;
        let req = request.to_owned_message();

        let agent = self.agents.get(&tenant_id, &req.id).await?;
        Ok(Response::new(agent_to_proto(&agent)))
    }

    #[instrument(skip(self))]
    async fn list_agents(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListAgentsRequest>,
    ) -> ServiceResult<ListAgentsResponse> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope_any(&ctx, &[SCOPE_AGENT_READ, SCOPE_AGENT_ADMIN])?;
        let req = request.to_owned_message();

        let (limit, after) = page_params(req.page.is_set().then(|| &*req.page))?;
        let (rows, total) = self.agents.list_page(&tenant_id, limit, after).await?;
        let next_page_token = next_page_token(
            rows.last().map(|r| (r.created_at, r.id.as_str())),
            rows.len(),
            limit,
        );

        Ok(Response::new(ListAgentsResponse {
            agents: rows.iter().map(agent_to_proto).collect(),
            page: Some(PageResponse {
                next_page_token,
                total_size: total as u32,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        }))
    }

    #[instrument(skip(self))]
    async fn update_agent(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UpdateAgentRequest>,
    ) -> ServiceResult<Agent> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope(&ctx, SCOPE_AGENT_ADMIN)?;
        let req = request.to_owned_message();

        let mut agent = self.agents.get(&tenant_id, &req.id).await?;

        if !req.status.is_empty() {
            validate_status(&req.status)?;
        }

        if !req.name.is_empty() && req.name != agent.name {
            agent = self.agents.set_name(&tenant_id, &req.id, &req.name).await?;
            self.rename_hydra_client(&tenant_id, &req.id, &req.name)
                .await;
        }

        if !req.status.is_empty() && req.status != agent.status {
            agent = self
                .agents
                .set_status(&tenant_id, &req.id, &req.status)
                .await?;
            // Big red button: disabling (or re-enabling) an agent takes effect
            // immediately for all of its act-tokens.
            self.authority.invalidate_agent(&req.id).await;
        }

        Ok(Response::new(agent_to_proto(&agent)))
    }

    #[instrument(skip(self))]
    async fn delete_agent(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DeleteAgentRequest>,
    ) -> ServiceResult<Empty> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope(&ctx, SCOPE_AGENT_ADMIN)?;
        let req = request.to_owned_message();

        // Cascades to delegations and act-token rows in Postgres.
        self.agents.delete(&tenant_id, &req.id).await?;

        if let Ok(ory_id) = self
            .mappings
            .get_ory_id(&tenant_id, BACKEND_HYDRA, &req.id)
            .await
            && let Err(err) = self.hydra.delete_oauth2_client(&ory_id).await
        {
            warn!(agent_id = %req.id, "best-effort hydra client delete failed: {}", err);
        }
        if let Err(err) = self
            .mappings
            .delete(&tenant_id, BACKEND_HYDRA, &req.id)
            .await
        {
            warn!(agent_id = %req.id, "best-effort id mapping delete failed: {}", err);
        }
        self.authority.invalidate_agent(&req.id).await;

        Ok(Response::new(Empty::default()))
    }

    #[instrument(skip(self))]
    async fn rotate_agent_secret(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RotateAgentSecretRequest>,
    ) -> ServiceResult<AgentSecret> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope(&ctx, SCOPE_AGENT_ADMIN)?;
        let req = request.to_owned_message();

        // Existence (and tenant ownership) check before touching Hydra.
        self.agents.get(&tenant_id, &req.id).await?;
        let ory_id = self
            .mappings
            .get_ory_id(&tenant_id, BACKEND_HYDRA, &req.id)
            .await?;

        let rotated = self
            .hydra
            .rotate_client_secret(&ory_id)
            .await
            .map_err(map_ory_error)?;
        let client_secret = rotated["client_secret"]
            .as_str()
            .ok_or_else(|| ServiceError::Internal("hydra response missing client_secret".into()))?
            .to_string();

        Ok(Response::new(AgentSecret {
            agent_id: req.id,
            client_secret,
            ..Default::default()
        }))
    }

    #[instrument(skip(self))]
    async fn create_agent_delegation(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateAgentDelegationRequest>,
    ) -> ServiceResult<AgentDelegation> {
        let tenant_id = require_tenant(&ctx)?;
        require_subject_type(&ctx, SubjectType::User)?;
        let req = request.to_owned_message();
        let auth = ctx.extensions().get::<AuthContext>().ok_or_else(|| {
            ServiceError::Unauthenticated("missing authentication context".into())
        })?;

        let agent = self.agents.get(&tenant_id, &req.agent_id).await?;
        if agent.status != AGENT_STATUS_ACTIVE {
            return Err(
                ServiceError::InvalidArgument(format!("agent {} is not active", agent.id)).into(),
            );
        }

        self.require_active_member(&tenant_id, &auth.subject)
            .await?;
        validate_delegation_scopes(&req.scope)?;
        let expires_at = from_proto_timestamp(&req.expires_at)
            .ok_or_else(|| ServiceError::InvalidArgument("expires_at is required".into()))?;
        if expires_at <= time::OffsetDateTime::now_utc() {
            return Err(
                ServiceError::InvalidArgument("expires_at must be in the future".into()).into(),
            );
        }

        let row = self
            .delegations
            .create(&tenant_id, &agent.id, &auth.subject, &req.scope, expires_at)
            .await?;
        Ok(Response::new(delegation_to_proto(&row)))
    }

    #[instrument(skip(self))]
    async fn list_agent_delegations(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListAgentDelegationsRequest>,
    ) -> ServiceResult<ListAgentDelegationsResponse> {
        let tenant_id = require_tenant(&ctx)?;
        let req = request.to_owned_message();
        let auth = ctx.extensions().get::<AuthContext>().ok_or_else(|| {
            ServiceError::Unauthenticated("missing authentication context".into())
        })?;

        let (limit, after) = page_params(req.page.is_set().then(|| &*req.page))?;
        let (rows, total) = if req.agent_id.is_empty() {
            // A user's own grants; only users grant delegations.
            require_subject_type(&ctx, SubjectType::User)?;
            self.delegations
                .list_page_by_user(&tenant_id, &auth.subject, limit, after)
                .await?
        } else {
            require_scope_any(&ctx, &[SCOPE_AGENT_READ, SCOPE_AGENT_ADMIN])?;
            self.delegations
                .list_page_by_agent(&tenant_id, &req.agent_id, limit, after)
                .await?
        };
        let next_page_token = next_page_token(
            rows.last().map(|r| (r.created_at, r.id.as_str())),
            rows.len(),
            limit,
        );

        Ok(Response::new(ListAgentDelegationsResponse {
            delegations: rows.iter().map(delegation_to_proto).collect(),
            page: Some(PageResponse {
                next_page_token,
                total_size: total as u32,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        }))
    }

    #[instrument(skip(self))]
    async fn revoke_agent_delegation(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RevokeAgentDelegationRequest>,
    ) -> ServiceResult<AgentDelegation> {
        let tenant_id = require_tenant(&ctx)?;
        let req = request.to_owned_message();
        let auth = ctx.extensions().get::<AuthContext>().ok_or_else(|| {
            ServiceError::Unauthenticated("missing authentication context".into())
        })?;

        let delegation = self.delegations.get(&tenant_id, &req.id).await?;
        let is_owner =
            auth.subject_type == SubjectType::User && auth.subject == delegation.user_identity_id;
        let is_admin = auth.scopes.iter().any(|s| s == SCOPE_AGENT_ADMIN);
        if !is_owner && !is_admin {
            return Err(ServiceError::PermissionDenied(
                "only the delegating user or an agent:admin may revoke".into(),
            )
            .into());
        }

        let row = self.delegations.revoke(&tenant_id, &req.id).await?;
        self.authority.invalidate_delegation(&req.id).await;
        Ok(Response::new(delegation_to_proto(&row)))
    }

    #[instrument(skip(self))]
    async fn mint_agent_act_token(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, MintAgentActTokenRequest>,
    ) -> ServiceResult<AgentActToken> {
        let tenant_id = require_tenant(&ctx)?;
        require_subject_type(&ctx, SubjectType::Agent)?;
        require_scope(&ctx, SCOPE_AGENT_ACT)?;
        let req = request.to_owned_message();
        let auth = ctx.extensions().get::<AuthContext>().ok_or_else(|| {
            ServiceError::Unauthenticated("missing authentication context".into())
        })?;

        // The middleware already rejects disabled agents at authentication;
        // re-check here so a direct call can never mint for a disabled agent.
        let agent = self.agents.get(&tenant_id, &auth.subject).await?;
        if agent.status != AGENT_STATUS_ACTIVE {
            return Err(ServiceError::PermissionDenied("agent is disabled".into()).into());
        }

        let delegation = self.delegations.get(&tenant_id, &req.delegation_id).await?;
        if delegation.agent_id != auth.subject {
            return Err(ServiceError::PermissionDenied(
                "delegation does not belong to this agent".into(),
            )
            .into());
        }
        let now = time::OffsetDateTime::now_utc();
        if delegation.revoked_at.is_some() {
            return Err(ServiceError::InvalidArgument("delegation has been revoked".into()).into());
        }
        if delegation.expires_at <= now {
            return Err(ServiceError::InvalidArgument("delegation has expired".into()).into());
        }
        self.require_active_member(&tenant_id, &delegation.user_identity_id)
            .await?;

        let (token, expires_in) = self.authority.mint(&delegation).await?;
        Ok(Response::new(AgentActToken {
            access_token: token,
            expires_in: expires_in.min(u32::MAX as u64) as u32,
            ..Default::default()
        }))
    }

    #[instrument(skip(self))]
    async fn introspect_agent_act_token(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, IntrospectAgentActTokenRequest>,
    ) -> ServiceResult<AgentActTokenIntrospection> {
        let tenant_id = require_tenant(&ctx)?;
        let req = request.to_owned_message();

        let resolution = self.authority.resolve_act_token(&req.token).await?;
        // Cross-tenant tokens introspect as inactive: existence must not leak.
        let active = resolution.filter(|res| res.tenant_id == tenant_id);
        let introspection = match active {
            Some(res) => AgentActTokenIntrospection {
                active: true,
                sub: res.user_identity_id,
                act: res.agent_id,
                tenant_id: res.tenant_id,
                scope: res.scopes,
                exp: opt_timestamp(Some(res.expires_at)),
                ..Default::default()
            },
            None => AgentActTokenIntrospection {
                active: false,
                ..Default::default()
            },
        };
        Ok(Response::new(introspection))
    }
}

impl AgentServiceImpl {
    /// Best-effort Hydra client rename. Hydra's update replaces the whole
    /// client, so the current client is fetched and merged rather than PUT
    /// partially (which would wipe grant types and scopes).
    async fn rename_hydra_client(&self, tenant_id: &str, agent_id: &str, name: &str) {
        let ory_id = match self
            .mappings
            .get_ory_id(tenant_id, BACKEND_HYDRA, agent_id)
            .await
        {
            Ok(ory_id) => ory_id,
            Err(err) => {
                warn!(%agent_id, "mapping lookup for hydra rename failed: {}", err);
                return;
            }
        };
        let mut client = match self.hydra.get_oauth2_client(&ory_id).await {
            Ok(client) => client,
            Err(err) => {
                warn!(%agent_id, "hydra fetch for rename failed: {}", err);
                return;
            }
        };
        client["client_name"] = Value::String(name.to_string());
        if let Err(err) = self.hydra.update_oauth2_client(&ory_id, client).await {
            warn!(%agent_id, "best-effort hydra client rename failed: {}", err);
        }
    }
}

fn agent_to_proto(row: &AgentRow) -> Agent {
    Agent {
        id: row.id.clone(),
        tenant_id: row.tenant_id.clone(),
        name: row.name.clone(),
        owner_identity_id: match row.owner_identity_id.as_deref() {
            Some(id) => id.to_owned(),
            None => String::new(),
        },
        status: row.status.clone(),
        created_at: timestamp(row.created_at),
        updated_at: timestamp(row.updated_at),
        ..Default::default()
    }
}

fn delegation_to_proto(row: &AgentDelegationRow) -> AgentDelegation {
    AgentDelegation {
        id: row.id.clone(),
        tenant_id: row.tenant_id.clone(),
        agent_id: row.agent_id.clone(),
        user_identity_id: row.user_identity_id.clone(),
        scope: row.scopes.clone(),
        expires_at: timestamp(row.expires_at),
        revoked_at: opt_timestamp(row.revoked_at),
        created_at: timestamp(row.created_at),
        ..Default::default()
    }
}

fn timestamp(t: time::OffsetDateTime) -> MessageField<Timestamp> {
    opt_timestamp(Some(t))
}

fn opt_timestamp(t: Option<time::OffsetDateTime>) -> MessageField<Timestamp> {
    t.map(|t| Timestamp {
        seconds: t.unix_timestamp(),
        nanos: t.nanosecond() as i32,
        ..Default::default()
    })
    .into()
}

fn from_proto_timestamp(field: &MessageField<Timestamp>) -> Option<time::OffsetDateTime> {
    if !field.is_set() {
        return None;
    }
    time::OffsetDateTime::from_unix_timestamp(field.seconds)
        .ok()
        .map(|t| t + time::Duration::nanoseconds(field.nanos as i64))
}

fn validate_status(status: &str) -> Result<(), ServiceError> {
    if status != AGENT_STATUS_ACTIVE && status != AGENT_STATUS_DISABLED {
        return Err(ServiceError::InvalidArgument(format!(
            "status must be {AGENT_STATUS_ACTIVE} or {AGENT_STATUS_DISABLED}"
        )));
    }
    Ok(())
}

/// Agent client scopes are gateway scopes (they gate gateway RPCs).
fn validate_client_scopes(scopes: &[String]) -> Result<(), ServiceError> {
    if scopes.is_empty() {
        return Err(ServiceError::InvalidArgument(
            "at least one scope is required".into(),
        ));
    }
    for scope in scopes {
        if !KNOWN_SCOPES.contains(&scope.as_str()) {
            return Err(ServiceError::InvalidArgument(format!(
                "unknown scope: {scope}"
            )));
        }
    }
    Ok(())
}

fn validate_delegation_scopes(scopes: &[String]) -> Result<(), ServiceError> {
    if scopes.is_empty() {
        return Err(ServiceError::InvalidArgument(
            "at least one scope is required".into(),
        ));
    }
    if scopes.len() > MAX_DELEGATION_SCOPES {
        return Err(ServiceError::InvalidArgument(format!(
            "at most {MAX_DELEGATION_SCOPES} scopes are allowed"
        )));
    }
    let mut seen = std::collections::HashSet::with_capacity(scopes.len());
    for scope in scopes {
        if scope.is_empty() || scope.len() > MAX_SCOPE_LEN || scope.chars().any(char::is_whitespace)
        {
            return Err(ServiceError::InvalidArgument(format!(
                "invalid scope: {scope:?}"
            )));
        }
        if !seen.insert(scope) {
            return Err(ServiceError::InvalidArgument(format!(
                "duplicate scope: {scope}"
            )));
        }
    }
    Ok(())
}

/// Extract (limit, keyset cursor) from an optional PageRequest.
fn page_params(
    page: Option<&crate::proto::iam::v1::PageRequest>,
) -> Result<(u32, Option<(time::OffsetDateTime, String)>), ServiceError> {
    let Some(page) = page else {
        return Ok((DEFAULT_PAGE_SIZE, None));
    };
    let limit = if page.page_size == 0 {
        DEFAULT_PAGE_SIZE
    } else {
        page.page_size.min(MAX_PAGE_SIZE)
    };
    let after = if page.page_token.is_empty() {
        None
    } else {
        Some(decode_page_token(&page.page_token)?)
    };
    Ok((limit, after))
}

/// Emit a next page token when the page came back full.
fn next_page_token(
    last: Option<(time::OffsetDateTime, &str)>,
    page_len: usize,
    limit: u32,
) -> String {
    if page_len == limit as usize {
        match last {
            Some((created_at, id)) => encode_page_token(created_at, id),
            None => String::new(),
        }
    } else {
        String::new()
    }
}

/// Encode a keyset cursor as an opaque page token.
fn encode_page_token(created_at: time::OffsetDateTime, id: &str) -> String {
    let raw = format!("{}:{id}", created_at.unix_timestamp_nanos());
    base64::engine::general_purpose::STANDARD.encode(raw.as_bytes())
}

/// Decode a page token back into its keyset cursor.
fn decode_page_token(token: &str) -> Result<(time::OffsetDateTime, String), ServiceError> {
    let invalid = || ServiceError::InvalidArgument("invalid page token".into());
    let raw = base64::engine::general_purpose::STANDARD
        .decode(token)
        .map_err(|_| invalid())?;
    let raw = String::from_utf8(raw).map_err(|_| invalid())?;
    let (nanos, id) = raw.split_once(':').ok_or_else(invalid)?;
    if id.is_empty() {
        return Err(invalid());
    }
    let nanos: i128 = nanos.parse().map_err(|_| invalid())?;
    let created_at =
        time::OffsetDateTime::from_unix_timestamp_nanos(nanos).map_err(|_| invalid())?;
    Ok((created_at, id.to_string()))
}

fn require_tenant(ctx: &RequestContext) -> Result<String, ServiceError> {
    ctx.extensions()
        .get::<TenantId>()
        .map(|t| t.0.clone())
        .ok_or_else(|| ServiceError::Unauthenticated("missing tenant".into()))
}

fn require_scope_any(ctx: &RequestContext, scopes: &[&str]) -> Result<(), ServiceError> {
    let auth = ctx
        .extensions()
        .get::<AuthContext>()
        .ok_or_else(|| ServiceError::Unauthenticated("missing authentication context".into()))?;
    if !auth.scopes.iter().any(|s| scopes.contains(&s.as_str())) {
        return Err(ServiceError::PermissionDenied(format!(
            "missing required scope: one of {}",
            scopes.join(", ")
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use buffa::bytes::Bytes;
    use buffa::view::MessageView;
    use buffa::{HasMessageView, Message};
    use serde_json::json;
    use sso_ory_client::error::OryClientError;
    use ulid::Ulid;

    use super::*;
    use crate::agent_tokens::AgentInvalidator;
    use crate::db::{AgentActTokenRow, AgentActTokenStore, IdMappingRow, TenantMembershipRow};
    use crate::proto::iam::v1::{AgentService, PageRequest};

    macro_rules! svc_req {
        ($id:ident, $req:expr, $ty:ty) => {
            let bytes = Bytes::from($req.encode_to_vec());
            let view = <$ty as HasMessageView>::View::decode_view(&bytes).unwrap();
            let $id = ServiceRequest::<$ty>::from_parts(&view, &bytes);
        };
    }

    const TENANT: &str = "t1";
    const USER: &str = "user-1";

    // -----------------------------------------------------------------------
    // Context helpers
    // -----------------------------------------------------------------------

    fn user_ctx(scopes: &[&str]) -> RequestContext {
        user_ctx_t(TENANT, USER, scopes)
    }

    fn user_ctx_t(tenant: &str, subject: &str, scopes: &[&str]) -> RequestContext {
        ctx(tenant, subject, SubjectType::User, scopes)
    }

    fn agent_ctx(agent_id: &str, scopes: &[&str]) -> RequestContext {
        ctx(TENANT, agent_id, SubjectType::Agent, scopes)
    }

    fn ctx(
        tenant: &str,
        subject: &str,
        subject_type: SubjectType,
        scopes: &[&str],
    ) -> RequestContext {
        let mut ctx = RequestContext::new(http::HeaderMap::new());
        ctx.extensions_mut().insert(TenantId(tenant.to_string()));
        ctx.extensions_mut().insert(AuthContext {
            tenant_id: tenant.to_string(),
            subject: subject.to_string(),
            subject_type,
            actor: None,
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            token_hash: "hash".into(),
            authentication_methods: Vec::new(),
        });
        ctx
    }

    fn future_timestamp() -> MessageField<Timestamp> {
        timestamp(time::OffsetDateTime::now_utc() + time::Duration::hours(1))
    }

    // -----------------------------------------------------------------------
    // Stubs
    // -----------------------------------------------------------------------

    #[derive(Default)]
    struct StubHydra {
        create_result: Mutex<Option<Result<Value, OryClientError>>>,
        create_payloads: Mutex<Vec<Value>>,
        get_results: Mutex<Vec<Result<Value, OryClientError>>>,
        update_calls: Mutex<Vec<(String, Value)>>,
        update_result: Mutex<Option<Result<Value, OryClientError>>>,
        delete_calls: Mutex<Vec<String>>,
        delete_result: Mutex<Option<Result<(), OryClientError>>>,
        rotate_result: Mutex<Option<Result<Value, OryClientError>>>,
    }

    #[async_trait]
    impl ClientCredentialHydra for StubHydra {
        async fn create_oauth2_client(&self, payload: Value) -> Result<Value, OryClientError> {
            self.create_payloads.lock().unwrap().push(payload.clone());
            if let Some(result) = self.create_result.lock().unwrap().take() {
                return result;
            }
            Ok(json!({
                "client_id": payload["client_id"],
                "client_name": payload["client_name"],
                "client_secret": "secret-123",
            }))
        }

        async fn get_oauth2_client(&self, _id: &str) -> Result<Value, OryClientError> {
            let mut results = self.get_results.lock().unwrap();
            if results.is_empty() {
                return Err(OryClientError::InvalidResponse("stub get".into()));
            }
            results.remove(0)
        }

        async fn update_oauth2_client(
            &self,
            id: &str,
            payload: Value,
        ) -> Result<Value, OryClientError> {
            self.update_calls
                .lock()
                .unwrap()
                .push((id.to_string(), payload.clone()));
            if let Some(result) = self.update_result.lock().unwrap().take() {
                return result;
            }
            Ok(payload)
        }

        async fn delete_oauth2_client(&self, id: &str) -> Result<(), OryClientError> {
            self.delete_calls.lock().unwrap().push(id.to_string());
            self.delete_result.lock().unwrap().take().unwrap_or(Ok(()))
        }

        async fn rotate_client_secret(&self, _id: &str) -> Result<Value, OryClientError> {
            self.rotate_result
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(OryClientError::InvalidResponse("stub rotate".into())))
        }
    }

    #[derive(Default)]
    struct StubAgents {
        rows: Mutex<HashMap<String, AgentRow>>,
    }

    impl StubAgents {
        fn get_row(&self, id: &str) -> Option<AgentRow> {
            self.rows.lock().unwrap().get(id).cloned()
        }

        fn len(&self) -> usize {
            self.rows.lock().unwrap().len()
        }
    }

    #[async_trait]
    impl AgentStore for StubAgents {
        async fn create(
            &self,
            tenant_id: &str,
            owner_identity_id: Option<&str>,
            name: &str,
        ) -> Result<AgentRow, DbError> {
            let now = time::OffsetDateTime::now_utc();
            let row = AgentRow {
                id: Ulid::new().to_string(),
                tenant_id: tenant_id.to_string(),
                owner_identity_id: owner_identity_id.map(String::from),
                name: name.to_string(),
                status: AGENT_STATUS_ACTIVE.to_string(),
                created_at: now,
                updated_at: now,
            };
            self.rows
                .lock()
                .unwrap()
                .insert(row.id.clone(), row.clone());
            Ok(row)
        }

        async fn get(&self, tenant_id: &str, id: &str) -> Result<AgentRow, DbError> {
            self.rows
                .lock()
                .unwrap()
                .get(id)
                .filter(|r| r.tenant_id == tenant_id)
                .cloned()
                .ok_or(DbError::AgentNotFound)
        }

        async fn get_status(&self, id: &str) -> Result<String, DbError> {
            self.rows
                .lock()
                .unwrap()
                .get(id)
                .map(|r| r.status.clone())
                .ok_or(DbError::AgentNotFound)
        }

        async fn set_name(
            &self,
            tenant_id: &str,
            id: &str,
            name: &str,
        ) -> Result<AgentRow, DbError> {
            let mut rows = self.rows.lock().unwrap();
            let row = rows
                .get_mut(id)
                .filter(|r| r.tenant_id == tenant_id)
                .ok_or(DbError::AgentNotFound)?;
            row.name = name.to_string();
            row.updated_at = time::OffsetDateTime::now_utc();
            Ok(row.clone())
        }

        async fn set_status(
            &self,
            tenant_id: &str,
            id: &str,
            status: &str,
        ) -> Result<AgentRow, DbError> {
            let mut rows = self.rows.lock().unwrap();
            let row = rows
                .get_mut(id)
                .filter(|r| r.tenant_id == tenant_id)
                .ok_or(DbError::AgentNotFound)?;
            row.status = status.to_string();
            row.updated_at = time::OffsetDateTime::now_utc();
            Ok(row.clone())
        }

        async fn delete(&self, tenant_id: &str, id: &str) -> Result<(), DbError> {
            let mut rows = self.rows.lock().unwrap();
            match rows.get(id).filter(|r| r.tenant_id == tenant_id) {
                Some(_) => {
                    rows.remove(id);
                    Ok(())
                }
                None => Err(DbError::AgentNotFound),
            }
        }

        async fn list_page(
            &self,
            tenant_id: &str,
            limit: u32,
            after: Option<(time::OffsetDateTime, String)>,
        ) -> Result<(Vec<AgentRow>, i64), DbError> {
            let rows = self.rows.lock().unwrap();
            let mut all: Vec<AgentRow> = rows
                .values()
                .filter(|r| r.tenant_id == tenant_id)
                .cloned()
                .collect();
            let total = all.len() as i64;
            all.sort_by(|a, b| {
                b.created_at
                    .cmp(&a.created_at)
                    .then_with(|| b.id.cmp(&a.id))
            });
            if let Some((cursor_ts, cursor_id)) = after {
                all.retain(|r| (r.created_at, r.id.as_str()) < (cursor_ts, cursor_id.as_str()));
            }
            all.truncate(limit as usize);
            Ok((all, total))
        }
    }

    #[derive(Default)]
    struct StubDelegations {
        rows: Mutex<Vec<AgentDelegationRow>>,
    }

    impl StubDelegations {
        fn list_page_by(
            rows: Vec<AgentDelegationRow>,
            limit: u32,
            after: Option<(time::OffsetDateTime, String)>,
        ) -> (Vec<AgentDelegationRow>, i64) {
            let total = rows.len() as i64;
            let mut rows = rows;
            rows.sort_by(|a, b| {
                b.created_at
                    .cmp(&a.created_at)
                    .then_with(|| b.id.cmp(&a.id))
            });
            if let Some((cursor_ts, cursor_id)) = after {
                rows.retain(|r| (r.created_at, r.id.as_str()) < (cursor_ts, cursor_id.as_str()));
            }
            rows.truncate(limit as usize);
            (rows, total)
        }
    }

    #[async_trait]
    impl AgentDelegationStore for StubDelegations {
        async fn create(
            &self,
            tenant_id: &str,
            agent_id: &str,
            user_identity_id: &str,
            scopes: &[String],
            expires_at: time::OffsetDateTime,
        ) -> Result<AgentDelegationRow, DbError> {
            let row = AgentDelegationRow {
                id: Ulid::new().to_string(),
                tenant_id: tenant_id.to_string(),
                agent_id: agent_id.to_string(),
                user_identity_id: user_identity_id.to_string(),
                scopes: scopes.to_vec(),
                expires_at,
                revoked_at: None,
                created_at: time::OffsetDateTime::now_utc(),
            };
            self.rows.lock().unwrap().push(row.clone());
            Ok(row)
        }

        async fn get(&self, tenant_id: &str, id: &str) -> Result<AgentDelegationRow, DbError> {
            self.rows
                .lock()
                .unwrap()
                .iter()
                .find(|r| r.id == id && r.tenant_id == tenant_id)
                .cloned()
                .ok_or(DbError::AgentDelegationNotFound)
        }

        async fn get_by_id(&self, id: &str) -> Result<AgentDelegationRow, DbError> {
            self.rows
                .lock()
                .unwrap()
                .iter()
                .find(|r| r.id == id)
                .cloned()
                .ok_or(DbError::AgentDelegationNotFound)
        }

        async fn revoke(&self, tenant_id: &str, id: &str) -> Result<AgentDelegationRow, DbError> {
            let mut rows = self.rows.lock().unwrap();
            let row = rows
                .iter_mut()
                .find(|r| r.id == id && r.tenant_id == tenant_id)
                .ok_or(DbError::AgentDelegationNotFound)?;
            if row.revoked_at.is_none() {
                row.revoked_at = Some(time::OffsetDateTime::now_utc());
            }
            Ok(row.clone())
        }

        async fn list_page_by_agent(
            &self,
            tenant_id: &str,
            agent_id: &str,
            limit: u32,
            after: Option<(time::OffsetDateTime, String)>,
        ) -> Result<(Vec<AgentDelegationRow>, i64), DbError> {
            let rows: Vec<_> = self
                .rows
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.tenant_id == tenant_id && r.agent_id == agent_id)
                .cloned()
                .collect();
            Ok(Self::list_page_by(rows, limit, after))
        }

        async fn list_page_by_user(
            &self,
            tenant_id: &str,
            user_identity_id: &str,
            limit: u32,
            after: Option<(time::OffsetDateTime, String)>,
        ) -> Result<(Vec<AgentDelegationRow>, i64), DbError> {
            let rows: Vec<_> = self
                .rows
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.tenant_id == tenant_id && r.user_identity_id == user_identity_id)
                .cloned()
                .collect();
            Ok(Self::list_page_by(rows, limit, after))
        }
    }

    #[derive(Default)]
    struct StubActTokens {
        rows: Mutex<Vec<AgentActTokenRow>>,
    }

    #[async_trait]
    impl AgentActTokenStore for StubActTokens {
        async fn insert(
            &self,
            token_hash: &str,
            delegation_id: &str,
            tenant_id: &str,
            agent_id: &str,
            user_identity_id: &str,
            scopes: &[String],
            expires_at: time::OffsetDateTime,
        ) -> Result<(), DbError> {
            self.rows.lock().unwrap().push(AgentActTokenRow {
                token_hash: token_hash.to_string(),
                delegation_id: delegation_id.to_string(),
                tenant_id: tenant_id.to_string(),
                agent_id: agent_id.to_string(),
                user_identity_id: user_identity_id.to_string(),
                scopes: scopes.to_vec(),
                expires_at,
                created_at: time::OffsetDateTime::now_utc(),
            });
            Ok(())
        }

        async fn get_by_hash(&self, token_hash: &str) -> Result<Option<AgentActTokenRow>, DbError> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|r| r.token_hash == token_hash)
                .cloned())
        }
    }

    #[derive(Default)]
    struct StubMemberships {
        rows: Mutex<HashMap<(String, String), TenantMembershipRow>>,
    }

    impl StubMemberships {
        fn add(&self, tenant_id: &str, identity_id: &str, state: &str) {
            let now = time::OffsetDateTime::now_utc();
            self.rows.lock().unwrap().insert(
                (tenant_id.to_string(), identity_id.to_string()),
                TenantMembershipRow {
                    tenant_id: tenant_id.to_string(),
                    identity_id: identity_id.to_string(),
                    schema_id: "employee".into(),
                    schema_version: 1,
                    traits: json!({}),
                    state: state.to_string(),
                    created_at: now,
                    updated_at: now,
                },
            );
        }
    }

    #[async_trait]
    impl TenantMembershipStore for StubMemberships {
        async fn upsert(
            &self,
            tenant_id: &str,
            identity_id: &str,
            _schema_id: &str,
            _schema_version: i64,
            _traits: Value,
        ) -> Result<TenantMembershipRow, DbError> {
            self.add(tenant_id, identity_id, "active");
            Ok(self
                .rows
                .lock()
                .unwrap()
                .get(&(tenant_id.to_string(), identity_id.to_string()))
                .unwrap()
                .clone())
        }

        async fn get(
            &self,
            tenant_id: &str,
            identity_id: &str,
        ) -> Result<TenantMembershipRow, DbError> {
            self.rows
                .lock()
                .unwrap()
                .get(&(tenant_id.to_string(), identity_id.to_string()))
                .cloned()
                .ok_or(DbError::MembershipNotFound)
        }

        async fn set_state(
            &self,
            tenant_id: &str,
            identity_id: &str,
            state: &str,
        ) -> Result<TenantMembershipRow, DbError> {
            let mut rows = self.rows.lock().unwrap();
            let row = rows
                .get_mut(&(tenant_id.to_string(), identity_id.to_string()))
                .ok_or(DbError::MembershipNotFound)?;
            row.state = state.to_string();
            Ok(row.clone())
        }

        async fn list_by_tenant(
            &self,
            tenant_id: &str,
        ) -> Result<Vec<TenantMembershipRow>, DbError> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .values()
                .filter(|r| r.tenant_id == tenant_id)
                .cloned()
                .collect())
        }
    }

    #[derive(Default)]
    struct StubMappings {
        rows: Mutex<HashMap<(String, String, String), String>>,
        create_error: Mutex<Option<DbError>>,
    }

    #[async_trait]
    impl IdMappingStore for StubMappings {
        async fn create(
            &self,
            tenant_id: &str,
            backend: &str,
            public_id: &str,
            ory_global_id: &str,
        ) -> Result<IdMappingRow, DbError> {
            if let Some(err) = self.create_error.lock().unwrap().take() {
                return Err(err);
            }
            self.rows.lock().unwrap().insert(
                (
                    tenant_id.to_string(),
                    backend.to_string(),
                    public_id.to_string(),
                ),
                ory_global_id.to_string(),
            );
            Ok(IdMappingRow {
                id: Ulid::new().to_string(),
                tenant_id: tenant_id.to_string(),
                backend: backend.to_string(),
                public_id: public_id.to_string(),
                ory_global_id: ory_global_id.to_string(),
                created_at: time::OffsetDateTime::now_utc(),
            })
        }

        async fn get_ory_id(
            &self,
            tenant_id: &str,
            backend: &str,
            public_id: &str,
        ) -> Result<String, DbError> {
            self.rows
                .lock()
                .unwrap()
                .get(&(
                    tenant_id.to_string(),
                    backend.to_string(),
                    public_id.to_string(),
                ))
                .cloned()
                .ok_or(DbError::MappingNotFound)
        }

        async fn get_public_id(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _ory_global_id: &str,
        ) -> Result<String, DbError> {
            Err(DbError::MappingNotFound)
        }

        async fn delete(
            &self,
            tenant_id: &str,
            backend: &str,
            public_id: &str,
        ) -> Result<(), DbError> {
            self.rows.lock().unwrap().remove(&(
                tenant_id.to_string(),
                backend.to_string(),
                public_id.to_string(),
            ));
            Ok(())
        }

        async fn list_public_ids(
            &self,
            _tenant_id: &str,
            _backend: &str,
        ) -> Result<Vec<String>, DbError> {
            Ok(Vec::new())
        }

        async fn get_tenant_id_by_ory_id(
            &self,
            _backend: &str,
            _ory_global_id: &str,
        ) -> Result<Option<String>, DbError> {
            Ok(None)
        }
    }

    // -----------------------------------------------------------------------
    // Fixture
    // -----------------------------------------------------------------------

    struct Fixture {
        svc: AgentServiceImpl,
        hydra: Arc<StubHydra>,
        mappings: Arc<StubMappings>,
        agents: Arc<StubAgents>,
        delegations: Arc<StubDelegations>,
        memberships: Arc<StubMemberships>,
        authority: Arc<AgentTokenAuthority>,
    }

    fn fixture() -> Fixture {
        let hydra = Arc::new(StubHydra::default());
        let mappings = Arc::new(StubMappings::default());
        let agents = Arc::new(StubAgents::default());
        let delegations = Arc::new(StubDelegations::default());
        let memberships = Arc::new(StubMemberships::default());
        let act_tokens = Arc::new(StubActTokens::default());
        let authority = Arc::new(AgentTokenAuthority::new(
            act_tokens,
            delegations.clone(),
            agents.clone(),
            AgentInvalidator::default(),
            std::time::Duration::from_secs(30),
            time::Duration::hours(1),
        ));
        let svc = AgentServiceImpl::new(
            hydra.clone(),
            mappings.clone(),
            agents.clone(),
            delegations.clone(),
            memberships.clone(),
            authority.clone(),
        );
        Fixture {
            svc,
            hydra,
            mappings,
            agents,
            delegations,
            memberships,
            authority,
        }
    }

    /// Seed an active agent with its hydra mapping, plus an active membership
    /// for the default user, and return the agent row.
    async fn seed_agent(f: &Fixture) -> AgentRow {
        let agent = f
            .agents
            .create(TENANT, Some(USER), "kanban-bot")
            .await
            .unwrap();
        f.mappings
            .create(TENANT, BACKEND_HYDRA, &agent.id, "ory-client-1")
            .await
            .unwrap();
        f.memberships.add(TENANT, USER, "active");
        agent
    }

    async fn seed_delegation(f: &Fixture, agent_id: &str) -> AgentDelegationRow {
        f.delegations
            .create(
                TENANT,
                agent_id,
                USER,
                &["kanban:read".to_string()],
                time::OffsetDateTime::now_utc() + time::Duration::hours(1),
            )
            .await
            .unwrap()
    }

    // -----------------------------------------------------------------------
    // CreateAgent
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn create_agent_requires_admin_scope() {
        let f = fixture();
        let req = CreateAgentRequest {
            name: "bot".into(),
            scope: vec![SCOPE_AGENT_ACT.into()],
            ..Default::default()
        };
        svc_req!(r, req, CreateAgentRequest);

        let err = f
            .svc
            .create_agent(user_ctx(&[SCOPE_AGENT_READ]), r)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::PermissionDenied, "{err:?}");
    }

    #[tokio::test]
    async fn create_agent_validates_name_and_scopes() {
        let f = fixture();

        let req = CreateAgentRequest {
            name: "".into(),
            scope: vec![SCOPE_AGENT_ACT.into()],
            ..Default::default()
        };
        svc_req!(r, req, CreateAgentRequest);
        let err = f
            .svc
            .create_agent(user_ctx(&[SCOPE_AGENT_ADMIN]), r)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("name is required"));

        let req = CreateAgentRequest {
            name: "bot".into(),
            scope: vec![],
            ..Default::default()
        };
        svc_req!(r, req, CreateAgentRequest);
        let err = f
            .svc
            .create_agent(user_ctx(&[SCOPE_AGENT_ADMIN]), r)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("at least one scope"));

        let req = CreateAgentRequest {
            name: "bot".into(),
            scope: vec!["kanban:read".into()],
            ..Default::default()
        };
        svc_req!(r, req, CreateAgentRequest);
        let err = f
            .svc
            .create_agent(user_ctx(&[SCOPE_AGENT_ADMIN]), r)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("unknown scope"));
    }

    #[tokio::test]
    async fn create_agent_returns_secret_once_and_registers_everything() {
        let f = fixture();
        let req = CreateAgentRequest {
            name: "kanban-bot".into(),
            scope: vec![SCOPE_AGENT_ACT.into(), SCOPE_AGENT_READ.into()],
            ..Default::default()
        };
        svc_req!(r, req, CreateAgentRequest);

        let agent = f
            .svc
            .create_agent(user_ctx(&[SCOPE_AGENT_ADMIN]), r)
            .await
            .unwrap()
            .body;

        assert_eq!(agent.tenant_id, TENANT);
        assert_eq!(agent.name, "kanban-bot");
        assert_eq!(agent.status, AGENT_STATUS_ACTIVE);
        assert_eq!(agent.owner_identity_id, USER);
        assert_eq!(agent.client_secret, "secret-123");
        assert!(agent.created_at.is_set());

        // Hydra client was created with client_id = agent id and the scopes.
        let payload = {
            let payloads = f.hydra.create_payloads.lock().unwrap();
            assert_eq!(payloads.len(), 1);
            payloads[0].clone()
        };
        assert_eq!(payload["client_id"], json!(agent.id));
        assert_eq!(payload["scope"], json!("agent:act agent:read"));
        assert_eq!(
            payload["grant_types"],
            json!([GRANT_TYPE_CLIENT_CREDENTIALS])
        );

        // Mapping resolves the agent id to the hydra client id.
        let ory_id = f
            .mappings
            .get_ory_id(TENANT, BACKEND_HYDRA, &agent.id)
            .await
            .unwrap();
        assert_eq!(ory_id, agent.id);

        // A subsequent GetAgent does not return the secret.
        let req = GetAgentRequest {
            id: agent.id.clone(),
            ..Default::default()
        };
        svc_req!(r, req, GetAgentRequest);
        let fetched = f
            .svc
            .get_agent(user_ctx(&[SCOPE_AGENT_READ]), r)
            .await
            .unwrap()
            .body;
        assert!(fetched.client_secret.is_empty());
    }

    #[tokio::test]
    async fn create_agent_compensates_when_hydra_fails() {
        let f = fixture();
        *f.hydra.create_result.lock().unwrap() = Some(Err(OryClientError::Ory {
            status: 500,
            message: "boom".into(),
        }));

        let req = CreateAgentRequest {
            name: "bot".into(),
            scope: vec![SCOPE_AGENT_ACT.into()],
            ..Default::default()
        };
        svc_req!(r, req, CreateAgentRequest);
        let err = f
            .svc
            .create_agent(user_ctx(&[SCOPE_AGENT_ADMIN]), r)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::Internal, "{err:?}");
        assert_eq!(f.agents.len(), 0, "agent row must be rolled back");
    }

    #[tokio::test]
    async fn create_agent_compensates_when_mapping_fails() {
        let f = fixture();
        *f.mappings.create_error.lock().unwrap() = Some(DbError::Sqlx(sqlx::Error::PoolTimedOut));

        let req = CreateAgentRequest {
            name: "bot".into(),
            scope: vec![SCOPE_AGENT_ACT.into()],
            ..Default::default()
        };
        svc_req!(r, req, CreateAgentRequest);
        let err = f
            .svc
            .create_agent(user_ctx(&[SCOPE_AGENT_ADMIN]), r)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::Internal, "{err:?}");
        assert_eq!(f.agents.len(), 0, "agent row must be rolled back");
        assert_eq!(
            f.hydra.delete_calls.lock().unwrap().len(),
            1,
            "hydra client must be rolled back"
        );
    }

    // -----------------------------------------------------------------------
    // GetAgent / ListAgents
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn get_agent_requires_read_scope_and_existing_agent() {
        let f = fixture();
        let agent = seed_agent(&f).await;

        let req = GetAgentRequest {
            id: agent.id.clone(),
            ..Default::default()
        };
        svc_req!(r, req, GetAgentRequest);
        let err = f.svc.get_agent(user_ctx(&[]), r).await.unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::PermissionDenied, "{err:?}");

        let req = GetAgentRequest {
            id: "missing".into(),
            ..Default::default()
        };
        svc_req!(r, req, GetAgentRequest);
        let err = f
            .svc
            .get_agent(user_ctx(&[SCOPE_AGENT_READ]), r)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::NotFound, "{err:?}");
    }

    #[tokio::test]
    async fn list_agents_paginates_with_keyset() {
        let f = fixture();
        for i in 0..3 {
            f.agents
                .create(TENANT, None, &format!("bot-{i}"))
                .await
                .unwrap();
        }

        let req = ListAgentsRequest {
            page: Some(PageRequest {
                page_size: 2,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        svc_req!(r, req, ListAgentsRequest);
        let page1 = f
            .svc
            .list_agents(user_ctx(&[SCOPE_AGENT_READ]), r)
            .await
            .unwrap()
            .body;
        assert_eq!(page1.agents.len(), 2);
        assert_eq!(page1.page.total_size, 3);
        assert!(!page1.page.next_page_token.is_empty());

        let req = ListAgentsRequest {
            page: Some(PageRequest {
                page_size: 2,
                page_token: page1.page.next_page_token.clone(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        svc_req!(r, req, ListAgentsRequest);
        let page2 = f
            .svc
            .list_agents(user_ctx(&[SCOPE_AGENT_READ]), r)
            .await
            .unwrap()
            .body;
        assert_eq!(page2.agents.len(), 1);
        assert!(page2.page.next_page_token.is_empty());
        assert_ne!(page1.agents[0].id, page2.agents[0].id);
    }

    #[tokio::test]
    async fn list_agents_rejects_invalid_page_token() {
        let f = fixture();
        let req = ListAgentsRequest {
            page: Some(PageRequest {
                page_token: "not-a-token".into(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        svc_req!(r, req, ListAgentsRequest);
        let err = f
            .svc
            .list_agents(user_ctx(&[SCOPE_AGENT_READ]), r)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::InvalidArgument, "{err:?}");
    }

    // -----------------------------------------------------------------------
    // UpdateAgent / DeleteAgent / RotateAgentSecret
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn update_agent_renames_and_merges_hydra_client() {
        let f = fixture();
        let agent = seed_agent(&f).await;
        f.hydra.get_results.lock().unwrap().push(Ok(json!({
            "client_id": "ory-client-1",
            "client_name": "kanban-bot",
            "scope": "agent:act",
        })));

        let req = UpdateAgentRequest {
            id: agent.id.clone(),
            name: "renamed-bot".into(),
            ..Default::default()
        };
        svc_req!(r, req, UpdateAgentRequest);
        let updated = f
            .svc
            .update_agent(user_ctx(&[SCOPE_AGENT_ADMIN]), r)
            .await
            .unwrap()
            .body;
        assert_eq!(updated.name, "renamed-bot");

        // The Hydra update carried the full merged client (scope preserved).
        let calls = f.hydra.update_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1["client_name"], json!("renamed-bot"));
        assert_eq!(calls[0].1["scope"], json!("agent:act"));
    }

    #[tokio::test]
    async fn update_agent_validates_status() {
        let f = fixture();
        let agent = seed_agent(&f).await;

        let req = UpdateAgentRequest {
            id: agent.id.clone(),
            status: "bogus".into(),
            ..Default::default()
        };
        svc_req!(r, req, UpdateAgentRequest);
        let err = f
            .svc
            .update_agent(user_ctx(&[SCOPE_AGENT_ADMIN]), r)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::InvalidArgument, "{err:?}");
    }

    #[tokio::test]
    async fn update_agent_disable_invalidates_act_tokens() {
        let f = fixture();
        let agent = seed_agent(&f).await;
        let delegation = seed_delegation(&f, &agent.id).await;

        let (token, _) = f.authority.mint(&delegation).await.unwrap();
        assert!(
            f.authority
                .resolve_act_token(&token)
                .await
                .unwrap()
                .is_some()
        );

        let req = UpdateAgentRequest {
            id: agent.id.clone(),
            status: AGENT_STATUS_DISABLED.into(),
            ..Default::default()
        };
        svc_req!(r, req, UpdateAgentRequest);
        let updated = f
            .svc
            .update_agent(user_ctx(&[SCOPE_AGENT_ADMIN]), r)
            .await
            .unwrap()
            .body;
        assert_eq!(updated.status, AGENT_STATUS_DISABLED);

        assert!(
            f.authority
                .resolve_act_token(&token)
                .await
                .unwrap()
                .is_none(),
            "disabling an agent must kill its act-tokens immediately"
        );
    }

    #[tokio::test]
    async fn delete_agent_removes_everything_and_invalidates() {
        let f = fixture();
        let agent = seed_agent(&f).await;
        let delegation = seed_delegation(&f, &agent.id).await;
        let (token, _) = f.authority.mint(&delegation).await.unwrap();

        let req = DeleteAgentRequest {
            id: agent.id.clone(),
            ..Default::default()
        };
        svc_req!(r, req, DeleteAgentRequest);
        f.svc
            .delete_agent(user_ctx(&[SCOPE_AGENT_ADMIN]), r)
            .await
            .unwrap();

        assert!(f.agents.get_row(&agent.id).is_none());
        assert_eq!(f.hydra.delete_calls.lock().unwrap().len(), 1);
        assert!(matches!(
            f.mappings
                .get_ory_id(TENANT, BACKEND_HYDRA, &agent.id)
                .await,
            Err(DbError::MappingNotFound)
        ));
        assert!(
            f.authority
                .resolve_act_token(&token)
                .await
                .unwrap()
                .is_none(),
            "deleting an agent must kill its act-tokens"
        );

        // Deleting again is a NotFound.
        let req = DeleteAgentRequest {
            id: agent.id.clone(),
            ..Default::default()
        };
        svc_req!(r, req, DeleteAgentRequest);
        let err = f
            .svc
            .delete_agent(user_ctx(&[SCOPE_AGENT_ADMIN]), r)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::NotFound, "{err:?}");
    }

    #[tokio::test]
    async fn rotate_agent_secret_returns_new_secret() {
        let f = fixture();
        let agent = seed_agent(&f).await;
        *f.hydra.rotate_result.lock().unwrap() = Some(Ok(json!({
            "client_id": "ory-client-1",
            "client_secret": "rotated-secret",
        })));

        let req = RotateAgentSecretRequest {
            id: agent.id.clone(),
            ..Default::default()
        };
        svc_req!(r, req, RotateAgentSecretRequest);
        let secret = f
            .svc
            .rotate_agent_secret(user_ctx(&[SCOPE_AGENT_ADMIN]), r)
            .await
            .unwrap()
            .body;
        assert_eq!(secret.agent_id, agent.id);
        assert_eq!(secret.client_secret, "rotated-secret");

        // Unknown agent is rejected before Hydra is touched.
        let req = RotateAgentSecretRequest {
            id: "missing".into(),
            ..Default::default()
        };
        svc_req!(r, req, RotateAgentSecretRequest);
        let err = f
            .svc
            .rotate_agent_secret(user_ctx(&[SCOPE_AGENT_ADMIN]), r)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::NotFound, "{err:?}");
    }

    // -----------------------------------------------------------------------
    // CreateAgentDelegation
    // -----------------------------------------------------------------------

    fn delegation_request(agent_id: &str) -> CreateAgentDelegationRequest {
        CreateAgentDelegationRequest {
            agent_id: agent_id.to_string(),
            scope: vec!["kanban:read".into()],
            expires_at: future_timestamp(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn create_delegation_requires_user_subject() {
        let f = fixture();
        let agent = seed_agent(&f).await;

        let req = delegation_request(&agent.id);
        svc_req!(r, req, CreateAgentDelegationRequest);
        let err = f
            .svc
            .create_agent_delegation(agent_ctx(&agent.id, &[]), r)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::PermissionDenied, "{err:?}");
        assert!(err.to_string().contains("requires a user subject"));
    }

    #[tokio::test]
    async fn create_delegation_rejects_disabled_agent() {
        let f = fixture();
        let agent = seed_agent(&f).await;
        f.agents
            .set_status(TENANT, &agent.id, AGENT_STATUS_DISABLED)
            .await
            .unwrap();

        let req = delegation_request(&agent.id);
        svc_req!(r, req, CreateAgentDelegationRequest);
        let err = f
            .svc
            .create_agent_delegation(user_ctx(&[]), r)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::InvalidArgument, "{err:?}");
        assert!(err.to_string().contains("not active"));
    }

    #[tokio::test]
    async fn create_delegation_requires_membership() {
        let f = fixture();
        let agent = f.agents.create(TENANT, None, "bot").await.unwrap();

        // No membership for the caller.
        let req = delegation_request(&agent.id);
        svc_req!(r, req, CreateAgentDelegationRequest);
        let err = f
            .svc
            .create_agent_delegation(user_ctx(&[]), r)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::PermissionDenied, "{err:?}");

        // Inactive membership is not enough.
        f.memberships.add(TENANT, USER, "inactive");
        let req = delegation_request(&agent.id);
        svc_req!(r, req, CreateAgentDelegationRequest);
        let err = f
            .svc
            .create_agent_delegation(user_ctx(&[]), r)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::PermissionDenied, "{err:?}");
        assert!(err.to_string().contains("not an active"));
    }

    #[tokio::test]
    async fn create_delegation_validates_expiry() {
        let f = fixture();
        let agent = seed_agent(&f).await;

        // Missing expires_at.
        let req = CreateAgentDelegationRequest {
            agent_id: agent.id.clone(),
            scope: vec!["kanban:read".into()],
            ..Default::default()
        };
        svc_req!(r, req, CreateAgentDelegationRequest);
        let err = f
            .svc
            .create_agent_delegation(user_ctx(&[]), r)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("expires_at is required"));

        // Past expires_at.
        let past = timestamp(time::OffsetDateTime::now_utc() - time::Duration::minutes(1));
        let req = CreateAgentDelegationRequest {
            agent_id: agent.id.clone(),
            scope: vec!["kanban:read".into()],
            expires_at: past,
            ..Default::default()
        };
        svc_req!(r, req, CreateAgentDelegationRequest);
        let err = f
            .svc
            .create_agent_delegation(user_ctx(&[]), r)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("in the future"));
    }

    #[tokio::test]
    async fn create_delegation_validates_scopes() {
        let f = fixture();
        let agent = seed_agent(&f).await;

        for (scopes, expected) in [
            (vec![], "at least one scope"),
            (vec!["bad scope".to_string()], "invalid scope"),
            (vec!["".to_string()], "invalid scope"),
            (
                vec!["kanban:read".to_string(), "kanban:read".to_string()],
                "duplicate scope",
            ),
        ] {
            let req = CreateAgentDelegationRequest {
                agent_id: agent.id.clone(),
                scope: scopes,
                expires_at: future_timestamp(),
                ..Default::default()
            };
            svc_req!(r, req, CreateAgentDelegationRequest);
            let err = f
                .svc
                .create_agent_delegation(user_ctx(&[]), r)
                .await
                .unwrap_err();
            assert!(
                err.to_string().contains(expected),
                "expected {expected}: {err}"
            );
        }
    }

    #[tokio::test]
    async fn create_delegation_happy_path() {
        let f = fixture();
        let agent = seed_agent(&f).await;

        let req = delegation_request(&agent.id);
        svc_req!(r, req, CreateAgentDelegationRequest);
        let delegation = f
            .svc
            .create_agent_delegation(user_ctx(&[]), r)
            .await
            .unwrap()
            .body;

        assert_eq!(delegation.tenant_id, TENANT);
        assert_eq!(delegation.agent_id, agent.id);
        assert_eq!(delegation.user_identity_id, USER);
        assert_eq!(delegation.scope, vec!["kanban:read"]);
        assert!(delegation.expires_at.is_set());
        assert!(!delegation.revoked_at.is_set());
    }

    // -----------------------------------------------------------------------
    // ListAgentDelegations / RevokeAgentDelegation
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn list_delegations_lists_own_grants() {
        let f = fixture();
        let agent = seed_agent(&f).await;
        seed_delegation(&f, &agent.id).await;
        seed_delegation(&f, &agent.id).await;
        f.delegations
            .create(
                TENANT,
                &agent.id,
                "user-2",
                &["kanban:read".to_string()],
                time::OffsetDateTime::now_utc() + time::Duration::hours(1),
            )
            .await
            .unwrap();

        let req = ListAgentDelegationsRequest::default();
        svc_req!(r, req, ListAgentDelegationsRequest);
        let resp = f
            .svc
            .list_agent_delegations(user_ctx(&[]), r)
            .await
            .unwrap()
            .body;
        assert_eq!(resp.delegations.len(), 2);
        assert_eq!(resp.page.total_size, 2);
        assert!(resp.delegations.iter().all(|d| d.user_identity_id == USER));

        // The own view is not available to non-user subjects.
        let req = ListAgentDelegationsRequest::default();
        svc_req!(r, req, ListAgentDelegationsRequest);
        let err = f
            .svc
            .list_agent_delegations(agent_ctx(&agent.id, &[]), r)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::PermissionDenied, "{err:?}");
    }

    #[tokio::test]
    async fn list_delegations_agent_view_requires_read_scope() {
        let f = fixture();
        let agent = seed_agent(&f).await;
        seed_delegation(&f, &agent.id).await;

        let req = ListAgentDelegationsRequest {
            agent_id: agent.id.clone(),
            ..Default::default()
        };
        svc_req!(r, req, ListAgentDelegationsRequest);
        let err = f
            .svc
            .list_agent_delegations(user_ctx(&[]), r)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::PermissionDenied, "{err:?}");

        let req = ListAgentDelegationsRequest {
            agent_id: agent.id.clone(),
            ..Default::default()
        };
        svc_req!(r, req, ListAgentDelegationsRequest);
        let resp = f
            .svc
            .list_agent_delegations(user_ctx(&[SCOPE_AGENT_READ]), r)
            .await
            .unwrap()
            .body;
        assert_eq!(resp.delegations.len(), 1);
    }

    #[tokio::test]
    async fn revoke_delegation_authz_paths() {
        let f = fixture();
        let agent = seed_agent(&f).await;
        let delegation = seed_delegation(&f, &agent.id).await;

        // A different user without agent:admin cannot revoke.
        let req = RevokeAgentDelegationRequest {
            id: delegation.id.clone(),
            ..Default::default()
        };
        svc_req!(r, req, RevokeAgentDelegationRequest);
        let err = f
            .svc
            .revoke_agent_delegation(user_ctx_t(TENANT, "user-2", &[]), r)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::PermissionDenied, "{err:?}");

        // An agent:admin caller can revoke someone else's grant.
        let req = RevokeAgentDelegationRequest {
            id: delegation.id.clone(),
            ..Default::default()
        };
        svc_req!(r, req, RevokeAgentDelegationRequest);
        let revoked = f
            .svc
            .revoke_agent_delegation(user_ctx_t(TENANT, "user-2", &[SCOPE_AGENT_ADMIN]), r)
            .await
            .unwrap()
            .body;
        assert!(revoked.revoked_at.is_set());

        // The owner can revoke (here the grant is already revoked; the call
        // still succeeds and returns the current state).
        let req = RevokeAgentDelegationRequest {
            id: delegation.id.clone(),
            ..Default::default()
        };
        svc_req!(r, req, RevokeAgentDelegationRequest);
        let revoked = f
            .svc
            .revoke_agent_delegation(user_ctx(&[]), r)
            .await
            .unwrap()
            .body;
        assert!(revoked.revoked_at.is_set());
    }

    // -----------------------------------------------------------------------
    // MintAgentActToken / IntrospectAgentActToken
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn mint_requires_agent_subject_and_act_scope() {
        let f = fixture();
        let agent = seed_agent(&f).await;
        let delegation = seed_delegation(&f, &agent.id).await;

        // A user subject cannot mint.
        let req = MintAgentActTokenRequest {
            delegation_id: delegation.id.clone(),
            ..Default::default()
        };
        svc_req!(r, req, MintAgentActTokenRequest);
        let err = f
            .svc
            .mint_agent_act_token(user_ctx(&[SCOPE_AGENT_ACT]), r)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::PermissionDenied, "{err:?}");

        // An agent without agent:act cannot mint.
        let req = MintAgentActTokenRequest {
            delegation_id: delegation.id.clone(),
            ..Default::default()
        };
        svc_req!(r, req, MintAgentActTokenRequest);
        let err = f
            .svc
            .mint_agent_act_token(agent_ctx(&agent.id, &[]), r)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::PermissionDenied, "{err:?}");
    }

    #[tokio::test]
    async fn mint_rejects_foreign_disabled_revoked_and_expired() {
        let f = fixture();
        let agent = seed_agent(&f).await;
        let other = f.agents.create(TENANT, None, "other-bot").await.unwrap();
        let delegation = seed_delegation(&f, &agent.id).await;

        // Another agent's delegation.
        let req = MintAgentActTokenRequest {
            delegation_id: delegation.id.clone(),
            ..Default::default()
        };
        svc_req!(r, req, MintAgentActTokenRequest);
        let err = f
            .svc
            .mint_agent_act_token(agent_ctx(&other.id, &[SCOPE_AGENT_ACT]), r)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::PermissionDenied, "{err:?}");

        // Revoked delegation.
        let revoked = seed_delegation(&f, &agent.id).await;
        f.delegations.revoke(TENANT, &revoked.id).await.unwrap();
        let req = MintAgentActTokenRequest {
            delegation_id: revoked.id.clone(),
            ..Default::default()
        };
        svc_req!(r, req, MintAgentActTokenRequest);
        let err = f
            .svc
            .mint_agent_act_token(agent_ctx(&agent.id, &[SCOPE_AGENT_ACT]), r)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("revoked"));

        // Expired delegation.
        let expired = f
            .delegations
            .create(
                TENANT,
                &agent.id,
                USER,
                &["kanban:read".to_string()],
                time::OffsetDateTime::now_utc() - time::Duration::minutes(1),
            )
            .await
            .unwrap();
        let req = MintAgentActTokenRequest {
            delegation_id: expired.id.clone(),
            ..Default::default()
        };
        svc_req!(r, req, MintAgentActTokenRequest);
        let err = f
            .svc
            .mint_agent_act_token(agent_ctx(&agent.id, &[SCOPE_AGENT_ACT]), r)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("expired"));

        // Disabled agent.
        f.agents
            .set_status(TENANT, &agent.id, AGENT_STATUS_DISABLED)
            .await
            .unwrap();
        let req = MintAgentActTokenRequest {
            delegation_id: delegation.id.clone(),
            ..Default::default()
        };
        svc_req!(r, req, MintAgentActTokenRequest);
        let err = f
            .svc
            .mint_agent_act_token(agent_ctx(&agent.id, &[SCOPE_AGENT_ACT]), r)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("disabled"));
    }

    #[tokio::test]
    async fn full_delegation_lifecycle_grant_mint_introspect_revoke() {
        let f = fixture();
        let agent = seed_agent(&f).await;

        // 1. The user grants the delegation.
        let req = delegation_request(&agent.id);
        svc_req!(r, req, CreateAgentDelegationRequest);
        let delegation = f
            .svc
            .create_agent_delegation(user_ctx(&[]), r)
            .await
            .unwrap()
            .body;

        // 2. The agent mints an act-token against it.
        let req = MintAgentActTokenRequest {
            delegation_id: delegation.id.clone(),
            ..Default::default()
        };
        svc_req!(r, req, MintAgentActTokenRequest);
        let act_token = f
            .svc
            .mint_agent_act_token(agent_ctx(&agent.id, &[SCOPE_AGENT_ACT]), r)
            .await
            .unwrap()
            .body;
        assert!(act_token.access_token.starts_with("sat_"));
        assert!(act_token.expires_in > 0);

        // 3. Introspection shows the token acting as the user, via the agent.
        let req = IntrospectAgentActTokenRequest {
            token: act_token.access_token.clone(),
            ..Default::default()
        };
        svc_req!(r, req, IntrospectAgentActTokenRequest);
        let introspection = f
            .svc
            .introspect_agent_act_token(user_ctx(&[]), r)
            .await
            .unwrap()
            .body;
        assert!(introspection.active);
        assert_eq!(introspection.sub, USER);
        assert_eq!(introspection.act, agent.id);
        assert_eq!(introspection.tenant_id, TENANT);
        assert_eq!(introspection.scope, vec!["kanban:read"]);
        assert!(introspection.exp.is_set());

        // 4. The user revokes the grant: the big red button.
        let req = RevokeAgentDelegationRequest {
            id: delegation.id.clone(),
            ..Default::default()
        };
        svc_req!(r, req, RevokeAgentDelegationRequest);
        f.svc
            .revoke_agent_delegation(user_ctx(&[]), r)
            .await
            .unwrap();

        // 5. The same token introspects as inactive immediately.
        let req = IntrospectAgentActTokenRequest {
            token: act_token.access_token.clone(),
            ..Default::default()
        };
        svc_req!(r, req, IntrospectAgentActTokenRequest);
        let introspection = f
            .svc
            .introspect_agent_act_token(user_ctx(&[]), r)
            .await
            .unwrap()
            .body;
        assert!(!introspection.active);

        // 6. Minting against the revoked grant fails too.
        let req = MintAgentActTokenRequest {
            delegation_id: delegation.id.clone(),
            ..Default::default()
        };
        svc_req!(r, req, MintAgentActTokenRequest);
        let err = f
            .svc
            .mint_agent_act_token(agent_ctx(&agent.id, &[SCOPE_AGENT_ACT]), r)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("revoked"));
    }

    #[tokio::test]
    async fn introspect_unknown_or_cross_tenant_token_is_inactive() {
        let f = fixture();
        let agent = seed_agent(&f).await;
        let delegation = seed_delegation(&f, &agent.id).await;
        let (token, _) = f.authority.mint(&delegation).await.unwrap();

        // Unknown token.
        let req = IntrospectAgentActTokenRequest {
            token: "sat_nope".into(),
            ..Default::default()
        };
        svc_req!(r, req, IntrospectAgentActTokenRequest);
        let resp = f
            .svc
            .introspect_agent_act_token(user_ctx(&[]), r)
            .await
            .unwrap()
            .body;
        assert!(!resp.active);

        // Valid token, wrong tenant: inactive, no existence leak.
        let req = IntrospectAgentActTokenRequest {
            token: token.clone(),
            ..Default::default()
        };
        svc_req!(r, req, IntrospectAgentActTokenRequest);
        let resp = f
            .svc
            .introspect_agent_act_token(user_ctx_t("t2", USER, &[]), r)
            .await
            .unwrap()
            .body;
        assert!(!resp.active);
    }

    #[tokio::test]
    async fn mint_requires_membership_still_active() {
        let f = fixture();
        let agent = seed_agent(&f).await;
        let delegation = seed_delegation(&f, &agent.id).await;

        // The delegating user leaves the tenant.
        f.memberships
            .set_state(TENANT, USER, "inactive")
            .await
            .unwrap();

        let req = MintAgentActTokenRequest {
            delegation_id: delegation.id.clone(),
            ..Default::default()
        };
        svc_req!(r, req, MintAgentActTokenRequest);
        let err = f
            .svc
            .mint_agent_act_token(agent_ctx(&agent.id, &[SCOPE_AGENT_ACT]), r)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::PermissionDenied, "{err:?}");
    }

    #[tokio::test]
    async fn page_token_round_trip_and_validation() {
        let now = time::OffsetDateTime::now_utc();
        let token = encode_page_token(now, "01JABC");
        let (ts, id) = decode_page_token(&token).unwrap();
        assert_eq!(ts.unix_timestamp_nanos(), now.unix_timestamp_nanos());
        assert_eq!(id, "01JABC");

        assert!(decode_page_token("!!!not-base64!!!").is_err());
        let no_sep = base64::engine::general_purpose::STANDARD.encode("no-separator");
        assert!(decode_page_token(&no_sep).is_err());
        let empty_id = base64::engine::general_purpose::STANDARD.encode("123:");
        assert!(decode_page_token(&empty_id).is_err());
        let bad_nanos = base64::engine::general_purpose::STANDARD.encode("abc:id");
        assert!(decode_page_token(&bad_nanos).is_err());
    }
}
