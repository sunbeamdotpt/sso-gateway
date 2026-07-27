use crate::harness::Gateway;

#[tokio::test]
async fn oauth2_discovery_returns_required_fields() {
    let gateway = Gateway::start().await;

    let discovery: serde_json::Value = gateway
        .http
        .get(format!(
            "{}/.well-known/openid-configuration",
            gateway.base_url
        ))
        .send()
        .await
        .expect("discovery request should succeed")
        .json()
        .await
        .expect("discovery should be json");

    assert_eq!(discovery["issuer"], gateway.base_url);
    assert!(
        discovery["authorization_endpoint"].as_str().is_some(),
        "authorization_endpoint is required"
    );
    assert!(
        discovery["token_endpoint"].as_str().is_some(),
        "token_endpoint is required"
    );
    assert!(
        discovery["userinfo_endpoint"].as_str().is_some(),
        "userinfo_endpoint is required for OIDC"
    );
    assert!(
        discovery["jwks_uri"].as_str().is_some(),
        "jwks_uri is required"
    );
    assert!(
        discovery["scopes_supported"]
            .as_array()
            .map(|a| !a.is_empty())
            .unwrap_or(false),
        "scopes_supported is required"
    );
    assert!(
        discovery["response_types_supported"]
            .as_array()
            .map(|a| !a.is_empty())
            .unwrap_or(false),
        "response_types_supported is required"
    );
    assert!(
        discovery["grant_types_supported"]
            .as_array()
            .map(|a| !a.is_empty())
            .unwrap_or(false),
        "grant_types_supported is required"
    );
    assert!(
        discovery["token_endpoint_auth_methods_supported"]
            .as_array()
            .map(|a| !a.is_empty())
            .unwrap_or(false),
        "token_endpoint_auth_methods_supported is required"
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn oauth2_jwks_returns_key_set() {
    let gateway = Gateway::start().await;

    let jwks: serde_json::Value = gateway
        .http
        .get(format!("{}/.well-known/jwks.json", gateway.base_url))
        .send()
        .await
        .expect("jwks request should succeed")
        .json()
        .await
        .expect("jwks should be json");

    assert!(
        jwks["keys"]
            .as_array()
            .map(|a| !a.is_empty())
            .unwrap_or(false),
        "jwks keys must be a non-empty array"
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn oauth2_client_credentials_returns_access_token() {
    let gateway = Gateway::start().await;
    let app = gateway
        .create_application(
            "oauth2-cc-conformance",
            &["https://localhost/callback"],
            &["client_credentials"],
            &["token"],
            &["openid"],
        )
        .await;
    let app_id = app["id"].as_str().expect("app id");
    let (client_id, client_secret) = gateway.rotate_secret(app_id).await;

    let token: serde_json::Value = gateway
        .http
        .post(format!("{}/oauth2/token", gateway.base_url))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", &client_id),
            ("client_secret", &client_secret),
            ("scope", "openid"),
        ])
        .send()
        .await
        .expect("token request should succeed")
        .json()
        .await
        .expect("token response should be json");

    assert!(
        token["access_token"].as_str().is_some(),
        "access_token is required"
    );
    assert_eq!(
        token["token_type"].as_str().map(|s| s.to_ascii_lowercase()),
        Some("bearer".to_string())
    );
    assert!(
        token["expires_in"].as_u64().is_some(),
        "expires_in is required"
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn oauth2_introspection_and_revocation_are_consistent() {
    let gateway = Gateway::start().await;
    let app = gateway
        .create_application(
            "oauth2-revoke-conformance",
            &["https://localhost/callback"],
            &["client_credentials"],
            &["token"],
            &["openid"],
        )
        .await;
    let app_id = app["id"].as_str().expect("app id");
    let (client_id, client_secret) = gateway.rotate_secret(app_id).await;

    let token: serde_json::Value = gateway
        .http
        .post(format!("{}/oauth2/token", gateway.base_url))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", &client_id),
            ("client_secret", &client_secret),
            ("scope", "openid"),
        ])
        .send()
        .await
        .expect("token request should succeed")
        .json()
        .await
        .expect("token response should be json");
    let access_token = token["access_token"].as_str().expect("access_token");

    let introspect: serde_json::Value = gateway
        .http
        .post(format!("{}/oauth2/introspect", gateway.base_url))
        .bearer_auth(&gateway.admin_token)
        .form(&[("token", access_token)])
        .send()
        .await
        .expect("introspect request should succeed")
        .json()
        .await
        .expect("introspect should be json");
    assert_eq!(introspect["active"], true);
    assert_eq!(introspect["token_type"], "Bearer");
    assert!(introspect["scope"].as_str().is_some());

    let revoke = gateway
        .http
        .post(format!("{}/oauth2/revoke", gateway.base_url))
        .form(&[
            ("token", access_token),
            ("client_id", &client_id),
            ("client_secret", &client_secret),
        ])
        .send()
        .await
        .expect("revoke request should succeed");
    assert!(revoke.status().is_success());

    let after_revoke: serde_json::Value = gateway
        .http
        .post(format!("{}/oauth2/introspect", gateway.base_url))
        .bearer_auth(&gateway.admin_token)
        .form(&[("token", access_token)])
        .send()
        .await
        .expect("introspect after revoke should succeed")
        .json()
        .await
        .expect("introspect should be json");
    assert_eq!(after_revoke["active"], false);

    gateway.shutdown().await;
}

#[tokio::test]
async fn oauth2_invalid_client_credentials_are_rejected() {
    let gateway = Gateway::start().await;

    let resp = gateway
        .http
        .post(format!("{}/oauth2/token", gateway.base_url))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "not-a-real-client"),
            ("client_secret", "not-a-real-secret"),
            ("scope", "openid"),
        ])
        .send()
        .await
        .expect("token request should complete");

    assert!(
        resp.status().is_client_error(),
        "invalid client credentials must be rejected"
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn oauth2_invalid_grant_type_is_rejected() {
    let gateway = Gateway::start().await;
    let app = gateway
        .create_application(
            "oauth2-grant-conformance",
            &["https://localhost/callback"],
            &["client_credentials"],
            &["token"],
            &["openid"],
        )
        .await;
    let app_id = app["id"].as_str().expect("app id");
    let (client_id, client_secret) = gateway.rotate_secret(app_id).await;

    let resp = gateway
        .http
        .post(format!("{}/oauth2/token", gateway.base_url))
        .form(&[
            ("grant_type", "invalid_grant"),
            ("client_id", &client_id),
            ("client_secret", &client_secret),
            ("scope", "openid"),
        ])
        .send()
        .await
        .expect("token request should complete");

    assert!(
        resp.status().is_client_error(),
        "invalid grant type must be rejected"
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn oauth2_authorize_rejects_unknown_client() {
    let gateway = Gateway::start().await;

    let resp = gateway
        .http
        .get(format!("{}/oauth2/auth", gateway.base_url))
        .query(&[
            ("client_id", "unknown-client-id"),
            ("response_type", "code"),
            ("redirect_uri", "http://localhost/callback"),
            ("scope", "openid"),
        ])
        .send()
        .await
        .expect("authorize request should complete");

    assert!(
        resp.status().is_client_error(),
        "unknown client_id must be rejected by the authorization endpoint"
    );

    gateway.shutdown().await;
}

const REDIRECT_URI: &str = "https://127.0.0.1:9999/callback";

/// MSC2965 end-to-end: a Matrix-style DCR client that never requests
/// `offline_access` still receives a usable refresh token, and the per-login
/// `urn:matrix:client:device:<id>` scope round-trips into the issued token
/// (zendrite extracts the device id from the granted scope). The gateway
/// registers Matrix clients with scope `*` (Hydra exact-matches scopes, so
/// the device scope could never be pre-registered), adds the refresh-token
/// grant at DCR time, and appends `offline_access` to the Matrix-shaped
/// authorize request before proxying to Hydra.
#[tokio::test]
async fn matrix_dcr_client_receives_usable_refresh_token() {
    let gateway = Gateway::start().await;

    // 1. Register a Matrix-style client through public DCR, exactly as
    //    Element X does: openid + a urn:matrix:client: scope, no
    //    offline_access, no device scope (it is per-login).
    let registration: serde_json::Value = gateway
        .http
        .post(format!("{}/oauth2/register", gateway.base_url))
        .json(&serde_json::json!({
            "client_name": "element-x-device",
            "redirect_uris": [REDIRECT_URI],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "scope": "openid urn:matrix:client:api:*",
            "token_endpoint_auth_method": "client_secret_post",
        }))
        .send()
        .await
        .expect("DCR request should succeed")
        .json()
        .await
        .expect("DCR response should be json");
    assert_eq!(
        registration["scope"], "*",
        "Matrix clients must be registered with wildcard scope"
    );
    let registered_grants: Vec<&str> = registration["grant_types"]
        .as_array()
        .expect("registered grant_types")
        .iter()
        .map(|v| v.as_str().expect("grant type should be a string"))
        .collect();
    assert!(
        registered_grants.contains(&"refresh_token"),
        "refresh_token grant must be added at DCR: {registered_grants:?}"
    );
    let client_id = registration["client_id"]
        .as_str()
        .expect("client_id")
        .to_string();
    let client_secret = registration["client_secret"]
        .as_str()
        .expect("client_secret")
        .to_string();

    // 2. Run the authorization-code flow requesting what Element requests at
    //    login: the api scope plus the per-login device scope (no
    //    offline_access — the gateway injects it). Consent grants whatever
    //    Hydra requested.
    let subject = ulid::Ulid::new().to_string();
    let result = gateway
        .authorization_code_flow_for_client(
            &subject,
            &client_id,
            &client_secret,
            // DCR sets the Hydra client_id to the public ULID.
            &client_id,
            REDIRECT_URI,
            &["code"],
            &[
                "openid",
                "urn:matrix:client:api:*",
                "urn:matrix:client:device:TESTDEV",
            ],
            None,
            true,
            None,
        )
        .await;
    assert!(
        result.token["access_token"].as_str().is_some_and(|t| !t.is_empty()),
        "token response must contain an access token: {}",
        result.token
    );
    // The device scope must round-trip into the granted token scope —
    // zendrite extracts the device id from it.
    let token_scope = result.token["scope"].as_str().unwrap_or_default();
    assert!(
        token_scope
            .split_whitespace()
            .any(|s| s == "urn:matrix:client:device:TESTDEV"),
        "token scope must carry the device scope: {token_scope}"
    );
    assert!(
        token_scope.split_whitespace().any(|s| s == "offline_access"),
        "token scope must carry offline_access: {token_scope}"
    );
    let refresh_token = result.token["refresh_token"]
        .as_str()
        .expect("Matrix flow must yield a refresh token");
    assert!(!refresh_token.is_empty());

    // 3. The refresh token actually works — the refresh grant returns a new
    //    access token, which also proves the client holds the refresh_token
    //    grant (fosite rejects the exchange otherwise).
    let refreshed = gateway
        .refresh_token_flow(refresh_token, &client_id, &client_secret)
        .await;
    assert!(
        refreshed.get("error").is_none(),
        "refresh grant must not error: {refreshed}"
    );
    assert!(
        refreshed["access_token"].as_str().is_some_and(|t| !t.is_empty()),
        "refresh grant must return a new access token: {refreshed}"
    );

    gateway.shutdown().await;
}

/// Probe for the DCR scope-ceiling question: does Hydra v25.4 reject an
/// authorize request whose scope exceeds the client's registered scope?
/// Registered scope here is exactly `openid`; the authorize request asks for
/// `openid profile`. Measured behavior: Hydra ENFORCES the ceiling and
/// redirects to the client redirect_uri with `error=invalid_scope`.
///
/// Consequence for MSC2965: the DCR hygiene (preserving `urn:matrix:client:*`
/// scopes and adding `offline_access` at registration) is load-bearing, not
/// cosmetic — the authorize-time `offline_access` injection only passes the
/// ceiling because registration put it there. Matrix clients registered
/// before that fix (registered scope lacks the Matrix/offline scopes) must
/// re-register, or their authorize requests fail with `invalid_scope`.
#[tokio::test]
async fn hydra_authorize_enforces_registered_scope_ceiling() {
    let gateway = Gateway::start().await;

    let registration: serde_json::Value = gateway
        .http
        .post(format!("{}/oauth2/register", gateway.base_url))
        .json(&serde_json::json!({
            "client_name": "ceiling-probe",
            "redirect_uris": [REDIRECT_URI],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "scope": "openid",
            "token_endpoint_auth_method": "client_secret_post",
        }))
        .send()
        .await
        .expect("DCR request should succeed")
        .json()
        .await
        .expect("DCR response should be json");
    assert_eq!(registration["scope"], "openid");
    let client_id = registration["client_id"]
        .as_str()
        .expect("client_id")
        .to_string();

    let no_redirect = reqwest::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("no-redirect client should build");
    let resp = no_redirect
        .get(format!("{}/oauth2/auth", gateway.base_url))
        .query(&[
            ("response_type", "code"),
            ("client_id", client_id.as_str()),
            ("redirect_uri", REDIRECT_URI),
            ("scope", "openid profile"),
            ("state", "ceiling-probe"),
        ])
        .send()
        .await
        .expect("authorize request should complete");

    assert!(
        resp.status().is_redirection(),
        "authorize must redirect with invalid_scope, got {:?}",
        resp.status()
    );
    let location = resp
        .headers()
        .get("location")
        .and_then(|h| h.to_str().ok())
        .expect("redirect location should exist")
        .to_string();
    assert!(
        location.starts_with(REDIRECT_URI),
        "scope violation must redirect to the client redirect_uri, got: {location}"
    );
    assert!(
        location.contains("error=invalid_scope"),
        "expected error=invalid_scope in the redirect, got: {location}"
    );
    assert!(
        !location.contains("login_challenge="),
        "authorize must not reach login with an out-of-ceiling scope: {location}"
    );

    gateway.shutdown().await;
}

/// The REAL Element Web/Desktop shape (SSO-018 prod evidence): the DCR
/// request carries NO Matrix scopes, so the client registers as plain
/// `openid` and the registration-time wildcard rule never fires. The
/// authorize-time self-heal must expand the client to scope `*` (plus the
/// refresh-token grant) when the first Matrix-shaped authorize arrives.
#[tokio::test]
async fn matrix_dcr_client_without_matrix_scopes_self_heals() {
    let gateway = Gateway::start().await;

    // 1. Register exactly like Element Web/Desktop: openid only.
    let registration: serde_json::Value = gateway
        .http
        .post(format!("{}/oauth2/register", gateway.base_url))
        .json(&serde_json::json!({
            "client_name": "element-web",
            "redirect_uris": [REDIRECT_URI],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "scope": "openid",
            "token_endpoint_auth_method": "client_secret_post",
        }))
        .send()
        .await
        .expect("DCR request should succeed")
        .json()
        .await
        .expect("DCR response should be json");
    assert_eq!(registration["scope"], "openid");
    let client_id = registration["client_id"]
        .as_str()
        .expect("client_id")
        .to_string();
    let client_secret = registration["client_secret"]
        .as_str()
        .expect("client_secret")
        .to_string();

    // 2. Run the full flow with the Matrix 1.19 login scopes. Without the
    //    self-heal this dies at authorize with invalid_scope (see
    //    hydra_authorize_enforces_registered_scope_ceiling).
    let subject = ulid::Ulid::new().to_string();
    let result = gateway
        .authorization_code_flow_for_client(
            &subject,
            &client_id,
            &client_secret,
            &client_id,
            REDIRECT_URI,
            &["code"],
            &[
                "openid",
                "urn:matrix:client:api:*",
                "urn:matrix:client:device:TESTDEV",
            ],
            None,
            true,
            None,
        )
        .await;
    let token_scope = result.token["scope"].as_str().unwrap_or_default();
    assert!(
        token_scope
            .split_whitespace()
            .any(|s| s == "urn:matrix:client:device:TESTDEV"),
        "token scope must carry the device scope: {token_scope}"
    );
    assert!(
        token_scope.split_whitespace().any(|s| s == "offline_access"),
        "token scope must carry offline_access: {token_scope}"
    );
    let refresh_token = result.token["refresh_token"]
        .as_str()
        .expect("self-healed Matrix flow must yield a refresh token");
    assert!(!refresh_token.is_empty());

    // 3. The heal persisted: the Hydra client now has scope `*` and the
    //    refresh-token grant.
    let healed: serde_json::Value = gateway
        .http
        .get(format!("{}/admin/clients/{client_id}", gateway.hydra_admin_url))
        .send()
        .await
        .expect("hydra client fetch should succeed")
        .json()
        .await
        .expect("hydra client should be json");
    assert_eq!(healed["scope"], "*");
    let healed_grants: Vec<&str> = healed["grant_types"]
        .as_array()
        .expect("grant_types")
        .iter()
        .map(|v| v.as_str().expect("grant type should be a string"))
        .collect();
    assert!(
        healed_grants.contains(&"refresh_token"),
        "healed client must hold the refresh_token grant: {healed_grants:?}"
    );

    // 4. And the refresh grant works end to end.
    let refreshed = gateway
        .refresh_token_flow(refresh_token, &client_id, &client_secret)
        .await;
    assert!(
        refreshed["access_token"].as_str().is_some_and(|t| !t.is_empty()),
        "refresh grant must return a new access token: {refreshed}"
    );

    gateway.shutdown().await;
}
