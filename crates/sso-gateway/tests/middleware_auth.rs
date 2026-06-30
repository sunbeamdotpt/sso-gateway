use std::sync::Arc;

use axum::{Extension, Router, middleware::from_fn, response::IntoResponse, routing::get};
use sso_gateway::{
    db::{AuditLogRepo, IdMappingRepo, TenantApiKeyRepo, bootstrap_system_tenant, create_pool},
    middleware::{TenantId, audit_middleware, auth_middleware, hash_api_key},
    oauth2::{Oauth2State, router as oauth2_router},
};
use sso_ory_client::{HydraClient, KratosClient};
use tokio::net::TcpListener;

mod support;

async fn echo(Extension(tenant): Extension<TenantId>) -> impl IntoResponse {
    tenant.0.clone()
}

async fn serve(
    app: Router,
) -> (
    tokio::task::JoinHandle<()>,
    String,
    tokio::sync::oneshot::Sender<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("random port should bind");
    let addr = listener.local_addr().expect("local addr should exist");
    let base = format!("http://{addr}");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("server should run");
    });
    (handle, base, shutdown_tx)
}

#[tokio::test]
async fn auth_middleware_public_path_bypass_and_rejections() {
    let (_pg, database_url) = support::start_postgres()
        .await
        .expect("postgres should start");

    let pool = create_pool(&database_url)
        .await
        .expect("database pool should be created");

    let tenant_id = ulid::Ulid::new().to_string();
    bootstrap_system_tenant(&pool, &tenant_id)
        .await
        .expect("system tenant should bootstrap");

    let api_keys = TenantApiKeyRepo::new(pool.clone());
    let api_key_secret = "integration-test-api-key";
    api_keys
        .create(
            &tenant_id,
            "test-key",
            &hash_api_key(api_key_secret),
            &[],
            None,
        )
        .await
        .expect("api key should be created");

    let hydra = Arc::new(
        HydraClient::new("http://localhost:1", "http://localhost:1")
            .expect("fake hydra client should build"),
    );
    let oauth_state = Arc::new(Oauth2State::new(
        hydra,
        IdMappingRepo::new(pool.clone()),
        "http://localhost".to_string(),
    ));
    let audit_repo = AuditLogRepo::new(pool.clone());
    let mappings = IdMappingRepo::new(pool.clone());
    let kratos = Arc::new(
        KratosClient::new_with_public("http://localhost:1", "http://localhost:1")
            .expect("fake kratos client should build"),
    );

    let app = Router::new()
        .route("/echo", get(echo))
        .merge(oauth2_router(oauth_state))
        .layer(from_fn(audit_middleware))
        .layer(from_fn(auth_middleware))
        .layer(Extension(api_keys))
        .layer(Extension(audit_repo))
        .layer(Extension(kratos))
        .layer(Extension(mappings));

    let (handle, base, shutdown_tx) = serve(app).await;
    let client = reqwest::Client::new();

    // Public discovery path bypasses API-key / tenant-id checks.
    let public_resp = client
        .get(format!("{base}/.well-known/openid-configuration"))
        .send()
        .await
        .expect("public request should complete");
    assert_eq!(public_resp.status(), reqwest::StatusCode::OK);

    // Protected path without any credentials is rejected.
    let missing_resp = client
        .get(format!("{base}/echo"))
        .send()
        .await
        .expect("missing creds request should complete");
    assert_eq!(missing_resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Invalid API key is rejected.
    let bad_key_resp = client
        .get(format!("{base}/echo"))
        .header("x-api-key", "not-the-secret")
        .send()
        .await
        .expect("bad key request should complete");
    assert_eq!(bad_key_resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Valid API key resolves the tenant and reaches the handler.
    let key_resp = client
        .get(format!("{base}/echo"))
        .header("x-api-key", api_key_secret)
        .send()
        .await
        .expect("valid key request should complete");
    assert_eq!(key_resp.status(), reqwest::StatusCode::OK);
    assert_eq!(
        key_resp.text().await.expect("body should be text"),
        tenant_id
    );

    // Explicit tenant header is accepted.
    let tenant_resp = client
        .get(format!("{base}/echo"))
        .header("x-tenant-id", &tenant_id)
        .send()
        .await
        .expect("tenant header request should complete");
    assert_eq!(tenant_resp.status(), reqwest::StatusCode::OK);

    // Invalid or empty tenant header is rejected at the middleware layer.
    let invalid_tenant_resp = client
        .get(format!("{base}/echo"))
        .header("x-tenant-id", "not-a-ulid")
        .send()
        .await
        .expect("invalid tenant request should complete");
    assert_eq!(
        invalid_tenant_resp.status(),
        reqwest::StatusCode::BAD_REQUEST
    );

    let empty_tenant_resp = client
        .get(format!("{base}/echo"))
        .header("x-tenant-id", "")
        .send()
        .await
        .expect("empty tenant request should complete");
    assert_eq!(empty_tenant_resp.status(), reqwest::StatusCode::BAD_REQUEST);

    // Give the audit middleware's spawned insert task time to complete.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let audit_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE resource = '/echo'")
            .fetch_one(&pool)
            .await
            .expect("audit log count should be readable");
    assert!(
        audit_count >= 1,
        "audit log should contain at least one /echo entry"
    );

    let _ = shutdown_tx.send(());
    handle.await.expect("server task should finish");
}
