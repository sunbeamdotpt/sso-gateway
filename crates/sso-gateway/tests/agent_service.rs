// SSO-027: tests may unwrap/expect freely; the panic/default bans target production code.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)
)]

//! End-to-end coverage for agent identities: the AgentService RPC surface
//! (backed by a real Hydra and Postgres) and the middleware classification of
//! agent client-credentials tokens and on-behalf-of act-tokens.

use std::sync::Arc;
use std::time::Duration as StdDuration;

use axum::{Extension, Router, middleware::from_fn, routing::get};
use connectrpc::Router as ConnectRouter;
use serde_json::{Value, json};
use sso_gateway::{
    agent_tokens::{AgentInvalidator, AgentTokenAuthority, AgentTokenResolver},
    auth::{
        AuthContext, AuthError, HydraTokenIntrospector, IntrospectionResult, TokenIntrospector,
    },
    db::{
        AGENT_STATUS_DISABLED, AgentActTokenRepo, AgentDelegationRepo, AgentRepo, IdMappingRepo,
        IdMappingStore, TenantMembershipRepo, bootstrap_system_tenant, create_pool,
    },
    middleware::auth_middleware,
    proto::iam::v1::AgentServiceExt,
    services::agent::AgentServiceImpl,
    session_token::SessionTokenSigner,
};
use sso_ory_client::HydraClient;
use sunbeam_g2v::{
    health::HealthRouter,
    router::ServiceRouter,
    server::{axum::bind_random_port, builder::ServerBuilder},
};
use time::format_description::well_known::Rfc3339;

mod support;

/// Echo the resolved AuthContext as `subject|subject_type|agent|delegation`.
async fn ctx(Extension(ctx): Extension<AuthContext>) -> String {
    let (agent_id, delegation_id) = ctx
        .actor
        .as_ref()
        .map(|a| (a.agent_id.as_str(), a.delegation_id.as_str()))
        .unwrap_or(("", ""));
    format!(
        "{}|{}|{}|{}",
        ctx.subject,
        ctx.subject_type.as_str(),
        agent_id,
        delegation_id
    )
}

/// Introspector that treats `TEST_TOKEN` as a human user (with agent admin
/// scopes) and delegates every other token to the real Hydra container.
struct UserOrHydraIntrospector {
    hydra: Arc<HydraClient>,
}

#[async_trait::async_trait]
impl TokenIntrospector for UserOrHydraIntrospector {
    async fn introspect(&self, token: &str) -> Result<IntrospectionResult, AuthError> {
        if token == support::TEST_TOKEN {
            return Ok(IntrospectionResult {
                active: true,
                sub: Some(support::TEST_SUBJECT.into()),
                scope: vec![
                    "openid".to_string(),
                    "agent:read".to_string(),
                    "agent:admin".to_string(),
                    "agent:act".to_string(),
                ],
                exp: None,
                authentication_methods: vec![],
            });
        }
        HydraTokenIntrospector::new(self.hydra.clone())
            .introspect(token)
            .await
    }
}

fn session_signer() -> SessionTokenSigner {
    SessionTokenSigner::new(
        "test-secret-that-is-at-least-32-bytes-long",
        3600,
        "https://gateway.example.com",
    )
}

#[tokio::test]
async fn agent_service_delegation_lifecycle_end_to_end() {
    let (_pg, database_url) = support::start_postgres()
        .await
        .expect("postgres should start");
    let (_hydra, hydra_admin_url, hydra_public_url) =
        support::start_hydra().await.expect("hydra should start");

    let pool = create_pool(&database_url, false)
        .await
        .expect("database pool should be created");
    let tenant_id = ulid::Ulid::new().to_string();
    bootstrap_system_tenant(&pool, &tenant_id)
        .await
        .expect("system tenant should bootstrap");

    // The delegating user resolves through Kratos so the middleware classifies
    // it as SubjectType::User (a hydra mapping would classify as Client).
    sqlx::query(
        "INSERT INTO id_mappings (id, tenant_id, backend, public_id, ory_global_id) \
         VALUES ($1, $2, 'kratos', $3, $3)",
    )
    .bind(ulid::Ulid::new().to_string())
    .bind(&tenant_id)
    .bind(support::TEST_SUBJECT)
    .execute(&pool)
    .await
    .expect("user subject mapping should be created");

    // Only active tenant members may grant delegations.
    TenantMembershipRepo::new(pool.clone())
        .upsert(
            &tenant_id,
            support::TEST_SUBJECT,
            "default",
            1,
            serde_json::json!({}),
        )
        .await
        .expect("membership should be created");

    let hydra = Arc::new(
        HydraClient::new(&hydra_admin_url, &hydra_public_url).expect("hydra client should build"),
    );
    let mappings = IdMappingRepo::new(pool.clone());
    let agents = Arc::new(AgentRepo::new(pool.clone()));
    let delegations = Arc::new(AgentDelegationRepo::new(pool.clone()));
    let authority = Arc::new(AgentTokenAuthority::new(
        Arc::new(AgentActTokenRepo::new(pool.clone())),
        delegations.clone(),
        agents.clone(),
        AgentInvalidator::new(None),
        // Long cache TTLs: the test asserts invalidation, not TTL expiry, is
        // what kills revoked tokens.
        StdDuration::from_secs(300),
        time::Duration::hours(1),
    ));

    let agent_service = Arc::new(AgentServiceImpl::new(
        hydra.clone(),
        Arc::new(mappings.clone()),
        agents.clone(),
        delegations.clone(),
        Arc::new(TenantMembershipRepo::new(pool.clone())),
        authority.clone(),
    ));

    let connect_router: ConnectRouter = agent_service.register(ConnectRouter::new());
    let service_router = ServiceRouter::from_router(connect_router);
    let server = ServerBuilder::new()
        .with_router(service_router)
        .with_health(HealthRouter::new())
        .build_axum()
        .expect("server should build");

    let app = server
        .app()
        .route("/ctx", get(ctx))
        .layer(from_fn(auth_middleware))
        .layer(Extension(session_signer()))
        .layer(Extension(Arc::new(UserOrHydraIntrospector {
            hydra: hydra.clone(),
        }) as Arc<dyn TokenIntrospector>))
        .layer(Extension(support::test_session_store()))
        .layer(Extension(authority.clone() as Arc<dyn AgentTokenResolver>))
        .layer(Extension(Arc::new(mappings) as Arc<dyn IdMappingStore>));

    let (listener, addr) = bind_random_port("127.0.0.1")
        .await
        .expect("random port should bind");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("server should run");
    });

    let client = reqwest::Client::new();
    let base = format!("http://{addr}");
    let user_auth = format!("Bearer {}", support::TEST_TOKEN);

    // --- CreateAgent: registers the agent and its Hydra client. -----------
    let create_resp = client
        .post(format!("{base}/iam.v1.AgentService/CreateAgent"))
        .header("authorization", &user_auth)
        .header("content-type", "application/json")
        .json(&json!({ "name": "kanban-bot", "scope": ["agent:act"] }))
        .send()
        .await
        .expect("create agent request should succeed");
    assert!(
        create_resp.status().is_success(),
        "create agent failed: {}",
        create_resp.text().await.unwrap_or_default()
    );
    let agent: Value = create_resp.json().await.expect("agent should be json");
    let agent_id = agent["id"].as_str().expect("agent id").to_string();
    let client_secret = agent["clientSecret"]
        .as_str()
        .expect("client secret returned exactly once")
        .to_string();
    assert_eq!(agent["tenantId"], tenant_id);
    assert_eq!(agent["status"], "active");

    // --- GetAgent / ListAgents happy paths. --------------------------------
    let get_resp = client
        .post(format!("{base}/iam.v1.AgentService/GetAgent"))
        .header("authorization", &user_auth)
        .header("content-type", "application/json")
        .json(&json!({ "id": agent_id }))
        .send()
        .await
        .expect("get agent request should succeed");
    assert!(get_resp.status().is_success(), "get agent failed");
    let fetched: Value = get_resp.json().await.expect("agent should be json");
    assert_eq!(fetched["name"], "kanban-bot");
    // The secret is never returned after creation.
    assert!(fetched["clientSecret"].is_null());

    let list_resp = client
        .post(format!("{base}/iam.v1.AgentService/ListAgents"))
        .header("authorization", &user_auth)
        .header("content-type", "application/json")
        .json(&json!({}))
        .send()
        .await
        .expect("list agents request should succeed");
    assert!(list_resp.status().is_success(), "list agents failed");
    let listed: Value = list_resp.json().await.expect("list should be json");
    assert_eq!(listed["agents"][0]["id"], agent_id);

    // --- The agent's own client-credentials token classifies as Agent. -----
    let cc_resp = client
        .post(format!("{hydra_public_url}/oauth2/token"))
        .basic_auth(&agent_id, Some(&client_secret))
        .form(&[("grant_type", "client_credentials"), ("scope", "agent:act")])
        .send()
        .await
        .expect("client credentials request should succeed");
    assert!(
        cc_resp.status().is_success(),
        "client credentials grant failed: {}",
        cc_resp.text().await.unwrap_or_default()
    );
    let cc_body: Value = cc_resp.json().await.expect("token response should be json");
    let agent_token = cc_body["access_token"]
        .as_str()
        .expect("access token")
        .to_string();

    let ctx_resp = client
        .get(format!("{base}/ctx"))
        .bearer_auth(&agent_token)
        .send()
        .await
        .expect("agent ctx request should succeed");
    assert_eq!(ctx_resp.status(), reqwest::StatusCode::OK);
    assert_eq!(
        ctx_resp.text().await.expect("ctx body"),
        format!("{agent_id}|agent||")
    );

    // --- The user pre-authorizes the agent (grant model). ------------------
    let expires_at = (time::OffsetDateTime::now_utc() + time::Duration::hours(24))
        .format(&Rfc3339)
        .expect("rfc3339");
    let delegation_resp = client
        .post(format!("{base}/iam.v1.AgentService/CreateAgentDelegation"))
        .header("authorization", &user_auth)
        .header("content-type", "application/json")
        .json(&json!({
            "agentId": agent_id,
            "scope": ["kanban:read", "kanban:write"],
            "expiresAt": expires_at,
        }))
        .send()
        .await
        .expect("create delegation request should succeed");
    assert!(
        delegation_resp.status().is_success(),
        "create delegation failed: {}",
        delegation_resp.text().await.unwrap_or_default()
    );
    let delegation: Value = delegation_resp
        .json()
        .await
        .expect("delegation should be json");
    let delegation_id = delegation["id"]
        .as_str()
        .expect("delegation id")
        .to_string();
    assert_eq!(delegation["userIdentityId"], support::TEST_SUBJECT);
    assert!(delegation["revokedAt"].is_null());

    // --- The agent mints an on-behalf-of act-token. ------------------------
    let mint_resp = client
        .post(format!("{base}/iam.v1.AgentService/MintAgentActToken"))
        .bearer_auth(&agent_token)
        .header("content-type", "application/json")
        .json(&json!({ "delegationId": delegation_id }))
        .send()
        .await
        .expect("mint request should succeed");
    assert!(
        mint_resp.status().is_success(),
        "mint act-token failed: {}",
        mint_resp.text().await.unwrap_or_default()
    );
    let minted: Value = mint_resp.json().await.expect("act-token should be json");
    let act_token = minted["accessToken"]
        .as_str()
        .expect("access token")
        .to_string();
    assert!(act_token.starts_with("sat_"));
    assert!(minted["expiresIn"].as_u64().expect("expires_in") > 0);

    // --- The act-token authenticates as the user, with the agent as actor. -
    let ctx_resp = client
        .get(format!("{base}/ctx"))
        .bearer_auth(&act_token)
        .send()
        .await
        .expect("act-token ctx request should succeed");
    assert_eq!(ctx_resp.status(), reqwest::StatusCode::OK);
    assert_eq!(
        ctx_resp.text().await.expect("ctx body"),
        format!(
            "{}|user|{}|{}",
            support::TEST_SUBJECT,
            agent_id,
            delegation_id
        )
    );

    // --- Introspection returns the RFC 7662-shaped claims. -----------------
    let introspect = || {
        client
            .post(format!(
                "{base}/iam.v1.AgentService/IntrospectAgentActToken"
            ))
            .header("authorization", &user_auth)
            .header("content-type", "application/json")
            .json(&json!({ "token": act_token }))
    };
    let introspect_resp = introspect()
        .send()
        .await
        .expect("introspect request should succeed");
    assert!(introspect_resp.status().is_success());
    let claims: Value = introspect_resp.json().await.expect("claims should be json");
    assert_eq!(claims["active"], true);
    assert_eq!(claims["sub"], support::TEST_SUBJECT);
    assert_eq!(claims["act"], agent_id);
    assert_eq!(claims["tenantId"], tenant_id);
    assert_eq!(claims["scope"], json!(["kanban:read", "kanban:write"]));

    // --- The big red button: revocation kills the act-token immediately. ---
    let revoke_resp = client
        .post(format!("{base}/iam.v1.AgentService/RevokeAgentDelegation"))
        .header("authorization", &user_auth)
        .header("content-type", "application/json")
        .json(&json!({ "id": delegation_id }))
        .send()
        .await
        .expect("revoke request should succeed");
    assert!(
        revoke_resp.status().is_success(),
        "revoke delegation failed: {}",
        revoke_resp.text().await.unwrap_or_default()
    );
    let revoked: Value = revoke_resp.json().await.expect("delegation should be json");
    assert!(revoked["revokedAt"].is_string());

    let introspect_resp = introspect()
        .send()
        .await
        .expect("introspect request should succeed");
    let claims: Value = introspect_resp.json().await.expect("claims should be json");
    // protojson omits default-valued fields, so an inactive result carries no
    // `active` key at all.
    assert!(
        !claims["active"].as_bool().unwrap_or_default(),
        "revoked token must be inactive"
    );

    let ctx_resp = client
        .get(format!("{base}/ctx"))
        .bearer_auth(&act_token)
        .send()
        .await
        .expect("act-token ctx request should succeed");
    assert_eq!(
        ctx_resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "revoked act-token must be rejected"
    );

    // Minting against a revoked delegation fails too.
    let mint_resp = client
        .post(format!("{base}/iam.v1.AgentService/MintAgentActToken"))
        .bearer_auth(&agent_token)
        .header("content-type", "application/json")
        .json(&json!({ "delegationId": delegation_id }))
        .send()
        .await
        .expect("mint request should succeed");
    assert!(
        !mint_resp.status().is_success(),
        "minting against a revoked delegation must fail"
    );

    // --- Disabling the agent kills its own client-credentials tokens. ------
    let update_resp = client
        .post(format!("{base}/iam.v1.AgentService/UpdateAgent"))
        .header("authorization", &user_auth)
        .header("content-type", "application/json")
        .json(&json!({ "id": agent_id, "status": "disabled" }))
        .send()
        .await
        .expect("update request should succeed");
    assert!(
        update_resp.status().is_success(),
        "disable agent failed: {}",
        update_resp.text().await.unwrap_or_default()
    );
    let disabled: Value = update_resp.json().await.expect("agent should be json");
    assert_eq!(disabled["status"], "disabled");

    let ctx_resp = client
        .get(format!("{base}/ctx"))
        .bearer_auth(&agent_token)
        .send()
        .await
        .expect("agent ctx request should succeed");
    assert_eq!(
        ctx_resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "disabled agent's own tokens must be rejected"
    );

    // --- DeleteAgent cascades; the agent is gone afterwards. ---------------
    let delete_resp = client
        .post(format!("{base}/iam.v1.AgentService/DeleteAgent"))
        .header("authorization", &user_auth)
        .header("content-type", "application/json")
        .json(&json!({ "id": agent_id }))
        .send()
        .await
        .expect("delete request should succeed");
    assert!(
        delete_resp.status().is_success(),
        "delete agent failed: {}",
        delete_resp.text().await.unwrap_or_default()
    );

    let get_resp = client
        .post(format!("{base}/iam.v1.AgentService/GetAgent"))
        .header("authorization", &user_auth)
        .header("content-type", "application/json")
        .json(&json!({ "id": agent_id }))
        .send()
        .await
        .expect("get agent request should succeed");
    assert!(
        !get_resp.status().is_success(),
        "deleted agent must not be fetchable"
    );

    let _ = shutdown_tx.send(());
    handle.await.expect("server task should finish");
}

/// Middleware-level coverage that does not need Hydra: act-tokens are minted
/// directly through the authority over Postgres repos.
#[tokio::test]
async fn act_token_middleware_paths() {
    let (_pg, database_url) = support::start_postgres()
        .await
        .expect("postgres should start");
    let pool = create_pool(&database_url, false)
        .await
        .expect("database pool should be created");
    let tenant_id = ulid::Ulid::new().to_string();
    bootstrap_system_tenant(&pool, &tenant_id)
        .await
        .expect("system tenant should bootstrap");
    // Maps TEST_SUBJECT via the hydra backend: with no agent row behind it,
    // the middleware classifies the token as a plain Client.
    support::bootstrap_test_subject_mapping(&pool, &tenant_id).await;

    let agents = Arc::new(AgentRepo::new(pool.clone()));
    let delegations = Arc::new(AgentDelegationRepo::new(pool.clone()));
    let authority = Arc::new(AgentTokenAuthority::new(
        Arc::new(AgentActTokenRepo::new(pool.clone())),
        delegations.clone(),
        agents.clone(),
        AgentInvalidator::new(None),
        StdDuration::from_secs(300),
        time::Duration::hours(1),
    ));

    let app = Router::new()
        .route("/ctx", get(ctx))
        .layer(from_fn(auth_middleware))
        .layer(Extension(session_signer()))
        .layer(Extension(support::test_introspector()))
        .layer(Extension(support::test_session_store()))
        .layer(Extension(authority.clone() as Arc<dyn AgentTokenResolver>))
        .layer(Extension(
            Arc::new(IdMappingRepo::new(pool.clone())) as Arc<dyn IdMappingStore>
        ));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("random port should bind");
    let addr = listener.local_addr().expect("local addr should exist");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("server should run");
    });

    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    // A hydra-backed subject with no agent row is a plain machine Client.
    let ctx_resp = client
        .get(format!("{base}/ctx"))
        .bearer_auth(support::TEST_TOKEN)
        .send()
        .await
        .expect("client token request should succeed");
    assert_eq!(ctx_resp.status(), reqwest::StatusCode::OK);
    assert_eq!(
        ctx_resp.text().await.expect("ctx body"),
        format!("{}|client||", support::TEST_SUBJECT)
    );

    // Seed an agent, a delegation, and mint an act-token directly.
    let agent = agents
        .create(&tenant_id, Some("owner-1"), "middleware-agent")
        .await
        .expect("agent should be created");
    let delegation = delegations
        .create(
            &tenant_id,
            &agent.id,
            "user-public-1",
            &["kanban:read".to_string()],
            time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        )
        .await
        .expect("delegation should be created");
    let (act_token, _) = authority
        .mint(&delegation)
        .await
        .expect("act-token should mint");

    let ctx_resp = client
        .get(format!("{base}/ctx"))
        .bearer_auth(&act_token)
        .send()
        .await
        .expect("act-token request should succeed");
    assert_eq!(ctx_resp.status(), reqwest::StatusCode::OK);
    assert_eq!(
        ctx_resp.text().await.expect("ctx body"),
        format!("user-public-1|user|{}|{}", agent.id, delegation.id)
    );

    // Revoking the delegation and invalidating kills the token immediately.
    delegations
        .revoke(&tenant_id, &delegation.id)
        .await
        .expect("delegation should revoke");
    authority.invalidate_delegation(&delegation.id).await;
    let ctx_resp = client
        .get(format!("{base}/ctx"))
        .bearer_auth(&act_token)
        .send()
        .await
        .expect("act-token request should succeed");
    assert_eq!(ctx_resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Disabling the agent kills act-tokens from its remaining delegations.
    let delegation = delegations
        .create(
            &tenant_id,
            &agent.id,
            "user-public-1",
            &["kanban:read".to_string()],
            time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        )
        .await
        .expect("delegation should be created");
    let (act_token, _) = authority
        .mint(&delegation)
        .await
        .expect("act-token should mint");
    agents
        .set_status(&tenant_id, &agent.id, AGENT_STATUS_DISABLED)
        .await
        .expect("agent should be disabled");
    authority.invalidate_agent(&agent.id).await;
    let ctx_resp = client
        .get(format!("{base}/ctx"))
        .bearer_auth(&act_token)
        .send()
        .await
        .expect("act-token request should succeed");
    assert_eq!(ctx_resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // An unknown opaque token falls through to Hydra introspection, which
    // rejects it.
    let ctx_resp = client
        .get(format!("{base}/ctx"))
        .bearer_auth("sat_0000000000000000000000000000000000000000000000000000000000000000")
        .send()
        .await
        .expect("unknown token request should succeed");
    assert_eq!(ctx_resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    let _ = shutdown_tx.send(());
    handle.await.expect("server task should finish");
}
