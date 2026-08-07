// SSO-027: tests may unwrap/expect freely; the panic/default bans target production code.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)
)]

//! End-to-end tests for the branded browser self-service surface, proxied
//! through to a real Ory Kratos (v25.4) container. The unit tests in
//! `services::handlers::self_service` pin the translation table against stub
//! upstreams; these tests prove the surface works against the real Kratos
//! route shapes.

use std::sync::Arc;

use sso_gateway::db::{
    TOKEN_TYPE_FLOW, TransientTokenRepo, TransientTokenStore, bootstrap_system_tenant, create_pool,
};
use sso_gateway::{
    config::SelfServicePaths,
    services::handlers::self_service::{SelfServiceState, router},
};
mod support;

const GATEWAY_URL: &str = "https://gateway.example.com";
const SYSTEM_TENANT_ULID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

async fn spawn_gateway(kratos_public_url: String) -> String {
    spawn_gateway_with_store(
        kratos_public_url,
        Arc::new(support::TestTransientTokenStore::default()),
    )
    .await
}

async fn spawn_gateway_with_store(
    kratos_public_url: String,
    transient: Arc<dyn TransientTokenStore>,
) -> String {
    let state = Arc::new(SelfServiceState::new(
        kratos_public_url,
        GATEWAY_URL.to_string(),
        SelfServicePaths::default(),
        transient,
        SYSTEM_TENANT_ULID.to_string(),
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gateway");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router(state)).await.unwrap();
    });
    format!("http://{addr}")
}

fn browser_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest client")
}

#[tokio::test(flavor = "multi_thread")]
async fn branded_login_init_returns_a_real_kratos_flow() {
    let (_kratos, _admin, kratos_public) =
        support::start_kratos().await.expect("kratos should start");
    let gateway = spawn_gateway(kratos_public).await;

    let response = browser_client()
        .get(format!("{gateway}/identity/login"))
        .header("accept", "application/json")
        .send()
        .await
        .expect("branded login request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    // A real Kratos flow JSON came back through the proxy.
    let body: serde_json::Value = response.json().await.expect("flow json");
    assert!(
        body.get("id").and_then(|id| id.as_str()).is_some(),
        "response should be a kratos flow: {body}"
    );
    assert!(
        body.get("ui").and_then(|ui| ui.get("action")).is_some(),
        "response should carry a ui container: {body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn branded_aal2_upgrade_error_passes_through() {
    let (_kratos, _admin, kratos_public) =
        support::start_kratos().await.expect("kratos should start");
    let gateway = spawn_gateway(kratos_public).await;

    // Without an AAL1 session, Kratos answers the AAL2 init with 401
    // `session_aal2_required`. The proxy must forward the upstream status and
    // body faithfully rather than collapsing it into a gateway error.
    let response = browser_client()
        .get(format!("{gateway}/identity/login?aal=aal2"))
        .header("accept", "application/json")
        .send()
        .await
        .expect("branded aal2 request");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = response.json().await.expect("error json");
    assert_eq!(
        body.pointer("/error/code").and_then(|code| code.as_u64()),
        Some(401),
        "expected the kratos aal2 error body: {body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn branded_login_init_passes_browser_redirects_through() {
    let (_kratos, _admin, kratos_public) =
        support::start_kratos().await.expect("kratos should start");
    let gateway = spawn_gateway(kratos_public).await;

    let response = browser_client()
        .get(format!("{gateway}/identity/login"))
        .header("accept", "text/html")
        .send()
        .await
        .expect("branded login request");
    // Kratos answers browser navigations with a 303 to the configured login
    // UI URL. That URL is application-owned, so the proxy must not touch it —
    // it must simply never point back at the Kratos host.
    assert_eq!(response.status(), reqwest::StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("303 must carry a location");
    assert!(
        !location.contains(":4433"),
        "location must not expose the kratos endpoint: {location}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn branded_webauthn_script_is_served_by_kratos() {
    let (_kratos, _admin, kratos_public) =
        support::start_kratos().await.expect("kratos should start");
    let gateway = spawn_gateway(kratos_public).await;

    let response = browser_client()
        .get(format!("{gateway}/identity/webauthn.js"))
        .send()
        .await
        .expect("branded webauthn request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body = response.text().await.expect("webauthn body");
    assert!(
        body.contains("webauthn") || body.contains("WebAuthn"),
        "expected the kratos webauthn script, got: {}",
        &body[..body.len().min(200)]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn kratos_shaped_email_link_bounces_to_the_branded_surface() {
    let (_kratos, _admin, kratos_public) =
        support::start_kratos().await.expect("kratos should start");
    let gateway = spawn_gateway(kratos_public).await;

    // Kratos emits recovery links as {base_url}/self-service/recovery?token=…
    // with its own path shape no matter what the gateway brands. The gateway
    // shim bounces the browser to the branded path without consuming the
    // token.
    let response = browser_client()
        .get(format!("{gateway}/self-service/recovery?token=t0&flow=f0"))
        .send()
        .await
        .expect("email link request");
    assert_eq!(response.status(), reqwest::StatusCode::FOUND);
    assert_eq!(
        response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok()),
        Some("https://gateway.example.com/identity/recovery?token=t0&flow=f0")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn kratos_init_paths_are_not_served_directly() {
    let (_kratos, _admin, kratos_public) =
        support::start_kratos().await.expect("kratos should start");
    let gateway = spawn_gateway(kratos_public).await;

    // Only the email-link shims exist under /self-service; init routes must
    // not be reachable in Kratos shape.
    let response = browser_client()
        .get(format!("{gateway}/self-service/login/browser?aal=aal2"))
        .send()
        .await
        .expect("kratos-shaped init request");
    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
}

/// SSO-041: a Kratos browser redirect that carries a flow id (the AAL2
/// step-up init is the production case) must be relayed with a gateway-minted
/// public ULID, and the mapping behind it must resolve — through the same
/// global lookup `resolve_flow` falls back to — to the raw Kratos flow id,
/// which Kratos then accepts.
#[tokio::test(flavor = "multi_thread")]
async fn proxied_flow_redirect_mints_resolvable_public_flow_id() {
    let (_postgres, db_url) = support::start_postgres()
        .await
        .expect("postgres should start");
    let (_kratos, _admin, kratos_public) =
        support::start_kratos().await.expect("kratos should start");
    let pool = create_pool(&db_url, false).await.expect("pool");
    bootstrap_system_tenant(&pool, SYSTEM_TENANT_ULID)
        .await
        .expect("system tenant should be bootstrapped");
    let store = Arc::new(TransientTokenRepo::new(pool));
    let gateway = spawn_gateway_with_store(kratos_public.clone(), store.clone()).await;

    let response = browser_client()
        .get(format!("{gateway}/identity/login"))
        .header("accept", "text/html")
        .send()
        .await
        .expect("branded login request");
    assert_eq!(response.status(), reqwest::StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("303 must carry a location")
        .to_string();
    let url = reqwest::Url::parse(&location).expect("location is an absolute url");
    let public_flow_id = url
        .query_pairs()
        .find(|(key, _)| key == "flow")
        .map(|(_, value)| value.into_owned())
        .expect("kratos flow redirect must carry a flow parameter");
    assert!(
        !public_flow_id.contains('-'),
        "public flow id should be a ULID, not the raw kratos UUID: {public_flow_id}"
    );

    // The public id resolves back to the raw Kratos flow id through the
    // global lookup resolve_flow falls back to...
    let (tenant, raw_flow_id) = store
        .get_ory_token_global("kratos", TOKEN_TYPE_FLOW, &public_flow_id)
        .await
        .expect("proxy-minted mapping should resolve");
    assert_eq!(tenant, SYSTEM_TENANT_ULID);

    // ...and Kratos accepts that raw id: the flow the browser was sent to
    // really exists upstream. Browser flows are cookie-bound, so the fetch
    // must carry the cookies Kratos issued on init (relayed by the proxy).
    let cookie = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|v| v.split(';').next())
        .collect::<Vec<_>>()
        .join("; ");
    let flow = browser_client()
        .get(format!(
            "{kratos_public}/self-service/login/flows?id={raw_flow_id}"
        ))
        .header("accept", "application/json")
        .header("cookie", cookie)
        .send()
        .await
        .expect("kratos flow fetch");
    assert_eq!(
        flow.status(),
        reqwest::StatusCode::OK,
        "kratos should resolve the raw flow id behind the public ULID"
    );
}
