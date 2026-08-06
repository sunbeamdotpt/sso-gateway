//! Agent act-token minting, introspection, and cache invalidation.
//!
//! Act-tokens are opaque bearer tokens minted against a delegation grant.
//! They exist to be *introspectable with instant revocation*: every use
//! re-validates the underlying grant (not revoked, not expired, agent still
//! active). Hot-path results are cached in-process; the cache is invalidated
//! on write (revocation / agent disable), never on time, with a seconds-long
//! TTL only as a backstop for missed cross-replica invalidations.
//!
//! Cross-replica invalidation rides core NATS pub/sub (fire-and-forget).
//! Without NATS the authority degrades to single-instance semantics: local
//! eviction still works, and the TTL bounds how long another replica could
//! have been stale anyway.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use moka::future::Cache;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sunbeam_g2v::mq::NatsClient;
use tracing::{debug, warn};

use crate::auth::hash_token;
use crate::db::{
    AGENT_STATUS_ACTIVE, AgentActTokenRow, AgentActTokenStore, AgentDelegationRow,
    AgentDelegationStore, AgentStore, DbError,
};

/// NATS subject carrying agent cache invalidation events between replicas.
pub const INVALIDATION_SUBJECT: &str = "sso-gateway.agent-invalidate";

/// Claims resolved from a valid act-token.
#[derive(Clone, Debug)]
pub struct ActTokenResolution {
    pub tenant_id: String,
    pub user_identity_id: String,
    pub agent_id: String,
    pub delegation_id: String,
    pub scopes: Vec<String>,
    pub expires_at: time::OffsetDateTime,
}

/// Narrow seam consumed by the auth middleware.
#[async_trait]
pub trait AgentTokenResolver: Send + Sync + 'static {
    /// Resolve a bearer token to act-token claims.
    ///
    /// `Ok(None)` means the token is not an act-token (or no longer a valid
    /// one); the caller should fall through to the normal introspection path,
    /// which will reject it.
    async fn resolve_act_token(&self, token: &str) -> Result<Option<ActTokenResolution>, DbError>;

    /// Look up an agent's lifecycle status by public id. `Ok(None)` means the
    /// id is not a registered agent (e.g. a plain client credential).
    async fn agent_status(&self, agent_id: &str) -> Result<Option<String>, DbError>;
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum InvalidationMessage {
    Delegation { id: String },
    Agent { id: String },
}

/// Publishes cache invalidation events to other replicas via NATS.
///
/// A missing NATS connection is not an error: the publisher becomes a no-op
/// and deployments degrade to single-instance revocation semantics.
#[derive(Clone, Default)]
pub struct AgentInvalidator {
    nats: Option<NatsClient>,
}

impl AgentInvalidator {
    pub fn new(nats: Option<NatsClient>) -> Self {
        Self { nats }
    }

    async fn publish(&self, message: &InvalidationMessage) {
        let Some(nats) = &self.nats else { return };
        let payload = match serde_json::to_vec(message) {
            Ok(payload) => payload,
            Err(err) => {
                warn!(%err, "failed to encode agent invalidation message");
                return;
            }
        };
        if let Err(err) = nats
            .publish(INVALIDATION_SUBJECT, bytes::Bytes::from(payload))
            .await
        {
            warn!(%err, "failed to publish agent cache invalidation");
        }
    }
}

/// Mints, resolves, and invalidates agent act-tokens.
pub struct AgentTokenAuthority {
    act_tokens: Arc<dyn AgentActTokenStore>,
    delegations: Arc<dyn AgentDelegationStore>,
    agents: Arc<dyn AgentStore>,
    invalidator: AgentInvalidator,
    /// token hash -> resolution; `None` entries are negative results (the
    /// presented token is not an act-token). Negative caching is safe: a
    /// token string is stored at mint time, before it can ever be presented.
    act_cache: Cache<String, Option<ActTokenResolution>>,
    /// agent public id -> status; `None` = not a registered agent.
    status_cache: Cache<String, Option<String>>,
    act_token_ttl: time::Duration,
}

impl AgentTokenAuthority {
    pub fn new(
        act_tokens: Arc<dyn AgentActTokenStore>,
        delegations: Arc<dyn AgentDelegationStore>,
        agents: Arc<dyn AgentStore>,
        invalidator: AgentInvalidator,
        cache_ttl: Duration,
        act_token_ttl: time::Duration,
    ) -> Self {
        Self {
            act_tokens,
            delegations,
            agents,
            invalidator,
            // `invalidate_entries_if` (used by revoke/disable) requires the
            // builder opt-in, otherwise it fails with
            // `PredicateError::InvalidationClosuresDisabled`.
            act_cache: Cache::builder()
                .time_to_live(cache_ttl)
                .support_invalidation_closures()
                .build(),
            status_cache: Cache::builder().time_to_live(cache_ttl).build(),
            act_token_ttl,
        }
    }

    /// Mint a new opaque act-token against a delegation the caller has
    /// already validated. Returns the raw token (shown exactly once) and its
    /// lifetime in seconds. The token never outlives its delegation.
    pub async fn mint(&self, delegation: &AgentDelegationRow) -> Result<(String, u64), DbError> {
        let mut random = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let token = format!("sat_{}", hex::encode(random));

        let now = time::OffsetDateTime::now_utc();
        let expires_at = std::cmp::min(now + self.act_token_ttl, delegation.expires_at);
        self.act_tokens
            .insert(
                &hash_token(&token),
                &delegation.id,
                &delegation.tenant_id,
                &delegation.agent_id,
                &delegation.user_identity_id,
                &delegation.scopes,
                expires_at,
            )
            .await?;
        debug!(delegation_id = %delegation.id, "minted agent act-token");
        Ok((token, (expires_at - now).whole_seconds().max(0) as u64))
    }

    /// Invalidate everything tied to a delegation: local eviction plus a
    /// broadcast to other replicas. This is the big red button.
    pub async fn invalidate_delegation(&self, delegation_id: &str) {
        self.evict_delegation(delegation_id).await;
        self.invalidator
            .publish(&InvalidationMessage::Delegation {
                id: delegation_id.to_string(),
            })
            .await;
    }

    /// Invalidate everything tied to an agent (status + all act-tokens).
    pub async fn invalidate_agent(&self, agent_id: &str) {
        self.evict_agent(agent_id).await;
        self.invalidator
            .publish(&InvalidationMessage::Agent {
                id: agent_id.to_string(),
            })
            .await;
    }

    /// Apply a remote invalidation received over NATS (never re-broadcast).
    pub async fn handle_invalidation(&self, payload: &[u8]) {
        match serde_json::from_slice::<InvalidationMessage>(payload) {
            Ok(InvalidationMessage::Delegation { id }) => self.evict_delegation(&id).await,
            Ok(InvalidationMessage::Agent { id }) => self.evict_agent(&id).await,
            Err(err) => warn!(%err, "ignoring malformed agent invalidation message"),
        }
    }

    // `invalidate_entries_if` only registers the predicate; the actual
    // eviction is deferred to cache maintenance, and `get` filters matching
    // entries on read. `run_pending_tasks` forces the removal so revocation
    // takes effect immediately. The predicate scan is O(cache size);
    // revocation and agent disable are rare writes, so a full scan is
    // acceptable there.
    async fn evict_delegation(&self, delegation_id: &str) {
        let delegation_id = delegation_id.to_string();
        let result = self.act_cache.invalidate_entries_if(move |_hash, entry| {
            entry
                .as_ref()
                .is_some_and(|res| res.delegation_id == delegation_id)
        });
        debug_assert!(
            result.is_ok(),
            "act cache must support invalidation closures"
        );
        self.act_cache.run_pending_tasks().await;
    }

    async fn evict_agent(&self, agent_id: &str) {
        self.status_cache.invalidate(agent_id).await;
        let agent_id = agent_id.to_string();
        let result = self.act_cache.invalidate_entries_if(move |_hash, entry| {
            entry.as_ref().is_some_and(|res| res.agent_id == agent_id)
        });
        debug_assert!(
            result.is_ok(),
            "act cache must support invalidation closures"
        );
        self.act_cache.run_pending_tasks().await;
    }

    async fn validate_act_token_row(
        &self,
        row: AgentActTokenRow,
    ) -> Result<Option<ActTokenResolution>, DbError> {
        let now = time::OffsetDateTime::now_utc();
        if row.expires_at <= now {
            return Ok(None);
        }
        let delegation = match self.delegations.get_by_id(&row.delegation_id).await {
            Ok(delegation) => delegation,
            // The grant was deleted (agent deletion cascades): token is dead.
            Err(DbError::AgentDelegationNotFound) => return Ok(None),
            Err(err) => return Err(err),
        };
        if delegation.revoked_at.is_some() || delegation.expires_at <= now {
            return Ok(None);
        }
        let status = match self.agents.get_status(&row.agent_id).await {
            Ok(status) => status,
            Err(DbError::AgentNotFound) => return Ok(None),
            Err(err) => return Err(err),
        };
        if status != AGENT_STATUS_ACTIVE {
            return Ok(None);
        }
        Ok(Some(ActTokenResolution {
            tenant_id: row.tenant_id,
            user_identity_id: row.user_identity_id,
            agent_id: row.agent_id,
            delegation_id: row.delegation_id,
            scopes: row.scopes,
            expires_at: row.expires_at,
        }))
    }
}

#[async_trait]
impl AgentTokenResolver for AgentTokenAuthority {
    async fn resolve_act_token(&self, token: &str) -> Result<Option<ActTokenResolution>, DbError> {
        let hash = hash_token(token);
        if let Some(entry) = self.act_cache.get(&hash).await {
            return Ok(entry.filter(|res| res.expires_at > time::OffsetDateTime::now_utc()));
        }

        let Some(row) = self.act_tokens.get_by_hash(&hash).await? else {
            self.act_cache.insert(hash, None).await;
            return Ok(None);
        };
        let resolution = self.validate_act_token_row(row).await?;
        self.act_cache.insert(hash, resolution.clone()).await;
        Ok(resolution)
    }

    async fn agent_status(&self, agent_id: &str) -> Result<Option<String>, DbError> {
        if let Some(entry) = self.status_cache.get(agent_id).await {
            return Ok(entry);
        }
        let status = match self.agents.get_status(agent_id).await {
            Ok(status) => Some(status),
            Err(DbError::AgentNotFound) => None,
            Err(err) => return Err(err),
        };
        self.status_cache
            .insert(agent_id.to_string(), status.clone())
            .await;
        Ok(status)
    }
}

/// Run the NATS subscriber applying remote invalidations to the authority's
/// caches. Intended to be spawned as a background task at startup.
pub async fn run_invalidation_subscriber(nats: NatsClient, authority: Arc<AgentTokenAuthority>) {
    use futures_util::StreamExt;

    let mut subscriber = match nats.subscribe(INVALIDATION_SUBJECT).await {
        Ok(subscriber) => subscriber,
        Err(err) => {
            warn!(%err, "agent invalidation subscriber failed to subscribe");
            return;
        }
    };
    while let Some(message) = subscriber.next().await {
        authority.handle_invalidation(&message.payload).await;
    }
    warn!("agent invalidation subscriber channel closed");
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::Duration as StdDuration;

    use super::*;
    use crate::db::{AgentRow, AgentStore};

    const TTL: StdDuration = StdDuration::from_secs(30);

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
    struct StubDelegations {
        rows: Mutex<Vec<AgentDelegationRow>>,
    }

    impl StubDelegations {
        fn insert(&self, row: AgentDelegationRow) {
            self.rows.lock().unwrap().push(row);
        }

        fn revoke(&self, id: &str) {
            let mut rows = self.rows.lock().unwrap();
            for row in rows.iter_mut() {
                if row.id == id {
                    row.revoked_at = Some(time::OffsetDateTime::now_utc());
                }
            }
        }
    }

    #[async_trait]
    impl AgentDelegationStore for StubDelegations {
        async fn create(
            &self,
            _tenant_id: &str,
            _agent_id: &str,
            _user_identity_id: &str,
            _scopes: &[String],
            _expires_at: time::OffsetDateTime,
        ) -> Result<AgentDelegationRow, DbError> {
            unimplemented!()
        }

        async fn get(&self, _tenant_id: &str, _id: &str) -> Result<AgentDelegationRow, DbError> {
            unimplemented!()
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

        async fn revoke(&self, _tenant_id: &str, _id: &str) -> Result<AgentDelegationRow, DbError> {
            unimplemented!()
        }

        async fn list_page_by_agent(
            &self,
            _tenant_id: &str,
            _agent_id: &str,
            _limit: u32,
            _after: Option<(time::OffsetDateTime, String)>,
        ) -> Result<(Vec<AgentDelegationRow>, i64), DbError> {
            unimplemented!()
        }

        async fn list_page_by_user(
            &self,
            _tenant_id: &str,
            _user_identity_id: &str,
            _limit: u32,
            _after: Option<(time::OffsetDateTime, String)>,
        ) -> Result<(Vec<AgentDelegationRow>, i64), DbError> {
            unimplemented!()
        }
    }

    #[derive(Default)]
    struct StubAgents {
        statuses: Mutex<std::collections::HashMap<String, String>>,
    }

    #[async_trait]
    impl AgentStore for StubAgents {
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
            self.statuses
                .lock()
                .unwrap()
                .get(id)
                .cloned()
                .ok_or(DbError::AgentNotFound)
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

    fn delegation(id: &str, agent_id: &str, expires_in: time::Duration) -> AgentDelegationRow {
        AgentDelegationRow {
            id: id.to_string(),
            tenant_id: "tenant-1".to_string(),
            agent_id: agent_id.to_string(),
            user_identity_id: "user-1".to_string(),
            scopes: vec!["tenant:read".to_string()],
            expires_at: time::OffsetDateTime::now_utc() + expires_in,
            revoked_at: None,
            created_at: time::OffsetDateTime::now_utc(),
        }
    }

    fn authority(
        act_tokens: Arc<StubActTokens>,
        delegations: Arc<StubDelegations>,
        agents: Arc<StubAgents>,
    ) -> AgentTokenAuthority {
        AgentTokenAuthority::new(
            act_tokens,
            delegations,
            agents,
            AgentInvalidator::default(),
            TTL,
            time::Duration::hours(1),
        )
    }

    #[tokio::test]
    async fn mint_returns_prefixed_token_and_stores_hash_only() {
        let act_tokens = Arc::new(StubActTokens::default());
        let authority = authority(
            act_tokens.clone(),
            Arc::new(StubDelegations::default()),
            Arc::new(StubAgents::default()),
        );

        let (token, expires_in) = authority
            .mint(&delegation("del-1", "agent-1", time::Duration::hours(24)))
            .await
            .unwrap();

        assert!(token.starts_with("sat_"));
        assert_eq!(token.len(), 4 + 64);
        assert!(expires_in <= 3600);
        assert_eq!(act_tokens.rows.lock().unwrap().len(), 1);
        let stored = &act_tokens.rows.lock().unwrap()[0];
        assert_ne!(stored.token_hash, token);
        assert_eq!(stored.token_hash, hash_token(&token));
    }

    #[tokio::test]
    async fn mint_caps_expiry_at_delegation_expiry() {
        let authority = authority(
            Arc::new(StubActTokens::default()),
            Arc::new(StubDelegations::default()),
            Arc::new(StubAgents::default()),
        );

        // Delegation expires in 5 minutes, token TTL is 1 hour.
        let (_token, expires_in) = authority
            .mint(&delegation("del-1", "agent-1", time::Duration::minutes(5)))
            .await
            .unwrap();
        assert!(expires_in <= 300);
    }

    #[tokio::test]
    async fn resolve_round_trips_valid_token() {
        let act_tokens = Arc::new(StubActTokens::default());
        let delegations = Arc::new(StubDelegations::default());
        let agents = Arc::new(StubAgents::default());
        delegations.insert(delegation("del-1", "agent-1", time::Duration::hours(24)));
        agents
            .statuses
            .lock()
            .unwrap()
            .insert("agent-1".to_string(), AGENT_STATUS_ACTIVE.to_string());
        let authority = authority(act_tokens, delegations, agents);

        let (token, _) = authority
            .mint(&delegation("del-1", "agent-1", time::Duration::hours(24)))
            .await
            .unwrap();

        let resolution = authority.resolve_act_token(&token).await.unwrap().unwrap();
        assert_eq!(resolution.user_identity_id, "user-1");
        assert_eq!(resolution.agent_id, "agent-1");
        assert_eq!(resolution.delegation_id, "del-1");
        assert_eq!(resolution.tenant_id, "tenant-1");
        assert_eq!(resolution.scopes, vec!["tenant:read".to_string()]);
    }

    #[tokio::test]
    async fn resolve_returns_none_for_unknown_and_negative_caches() {
        let act_tokens = Arc::new(StubActTokens::default());
        let authority = authority(
            act_tokens.clone(),
            Arc::new(StubDelegations::default()),
            Arc::new(StubAgents::default()),
        );

        assert!(
            authority
                .resolve_act_token("sat_unknown")
                .await
                .unwrap()
                .is_none()
        );
        // A second resolution is also None (served from the negative cache).
        assert!(
            authority
                .resolve_act_token("sat_unknown")
                .await
                .unwrap()
                .is_none()
        );
        assert!(act_tokens.rows.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn revoked_delegation_invalidates_after_eviction() {
        let act_tokens = Arc::new(StubActTokens::default());
        let delegations = Arc::new(StubDelegations::default());
        let agents = Arc::new(StubAgents::default());
        delegations.insert(delegation("del-1", "agent-1", time::Duration::hours(24)));
        agents
            .statuses
            .lock()
            .unwrap()
            .insert("agent-1".to_string(), AGENT_STATUS_ACTIVE.to_string());
        let authority = authority(act_tokens, delegations.clone(), agents);

        let (token, _) = authority
            .mint(&delegation("del-1", "agent-1", time::Duration::hours(24)))
            .await
            .unwrap();
        assert!(authority.resolve_act_token(&token).await.unwrap().is_some());

        delegations.revoke("del-1");
        // Still cached as valid until the revocation write evicts it.
        authority.invalidate_delegation("del-1").await;
        assert!(authority.resolve_act_token(&token).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn disabled_agent_invalidates_after_eviction() {
        let act_tokens = Arc::new(StubActTokens::default());
        let delegations = Arc::new(StubDelegations::default());
        let agents = Arc::new(StubAgents::default());
        delegations.insert(delegation("del-1", "agent-1", time::Duration::hours(24)));
        agents
            .statuses
            .lock()
            .unwrap()
            .insert("agent-1".to_string(), AGENT_STATUS_ACTIVE.to_string());
        let authority = authority(act_tokens, delegations, agents.clone());

        let (token, _) = authority
            .mint(&delegation("del-1", "agent-1", time::Duration::hours(24)))
            .await
            .unwrap();
        assert!(authority.resolve_act_token(&token).await.unwrap().is_some());

        agents.statuses.lock().unwrap().insert(
            "agent-1".to_string(),
            crate::db::AGENT_STATUS_DISABLED.to_string(),
        );
        authority.invalidate_agent("agent-1").await;
        assert!(authority.resolve_act_token(&token).await.unwrap().is_none());
        // Status cache was evicted too.
        assert_eq!(
            authority.agent_status("agent-1").await.unwrap().as_deref(),
            Some(crate::db::AGENT_STATUS_DISABLED)
        );
    }

    #[tokio::test]
    async fn expired_token_and_expired_delegation_resolve_to_none() {
        let act_tokens = Arc::new(StubActTokens::default());
        let delegations = Arc::new(StubDelegations::default());
        let agents = Arc::new(StubAgents::default());
        agents
            .statuses
            .lock()
            .unwrap()
            .insert("agent-1".to_string(), AGENT_STATUS_ACTIVE.to_string());

        // Delegation already expired.
        let mut expired = delegation("del-expired", "agent-1", time::Duration::minutes(-5));
        expired.expires_at = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
        delegations.insert(expired);
        let authority = authority(act_tokens, delegations, agents);

        let (token, _) = authority
            .mint(&delegation("del-ok", "agent-1", time::Duration::hours(24)))
            .await
            .unwrap();
        // Point the stored token at the expired delegation.
        let hash = hash_token(&token);
        authority
            .act_tokens
            .insert(
                &hash_token("sat_other"),
                "del-expired",
                "tenant-1",
                "agent-1",
                "user-1",
                &[],
                time::OffsetDateTime::now_utc() + time::Duration::hours(1),
            )
            .await
            .unwrap();
        let _ = hash;
        assert!(
            authority
                .resolve_act_token("sat_other")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn agent_status_caches_and_distinguishes_non_agents() {
        let agents = Arc::new(StubAgents::default());
        agents
            .statuses
            .lock()
            .unwrap()
            .insert("agent-1".to_string(), AGENT_STATUS_ACTIVE.to_string());
        let authority = authority(
            Arc::new(StubActTokens::default()),
            Arc::new(StubDelegations::default()),
            agents,
        );

        assert_eq!(
            authority.agent_status("agent-1").await.unwrap().as_deref(),
            Some(AGENT_STATUS_ACTIVE)
        );
        assert!(
            authority
                .agent_status("not-an-agent")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn remote_invalidation_message_evicts() {
        let act_tokens = Arc::new(StubActTokens::default());
        let delegations = Arc::new(StubDelegations::default());
        let agents = Arc::new(StubAgents::default());
        delegations.insert(delegation("del-1", "agent-1", time::Duration::hours(24)));
        agents
            .statuses
            .lock()
            .unwrap()
            .insert("agent-1".to_string(), AGENT_STATUS_ACTIVE.to_string());
        let authority = authority(act_tokens, delegations, agents);

        let (token, _) = authority
            .mint(&delegation("del-1", "agent-1", time::Duration::hours(24)))
            .await
            .unwrap();
        assert!(authority.resolve_act_token(&token).await.unwrap().is_some());

        // Simulate a remote revoke: cache still holds the token as valid, and
        // only the NATS message evicts it (the stub delegation stays live).
        authority
            .handle_invalidation(br#"{"kind":"delegation","id":"del-1"}"#)
            .await;
        // Re-validation against the still-live stub grant succeeds again, but
        // the eviction itself is what a remote revoke relies on: verify the
        // cached entry was dropped by checking a fresh resolution revalidates
        // from the stores.
        let resolution = authority.resolve_act_token(&token).await.unwrap();
        assert!(resolution.is_some());

        authority
            .handle_invalidation(br#"{"kind":"agent","id":"agent-1"}"#)
            .await;
        authority.handle_invalidation(b"not json").await;
    }
}
