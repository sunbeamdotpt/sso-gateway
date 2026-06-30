use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::json;

use crate::harness::Gateway;

#[tokio::test]
async fn oidc_discovery_has_oidc_required_fields() {
    let gateway = Gateway::start().await;

    let discovery: serde_json::Value = gateway
        .http
        .get(format!("{}/.well-known/openid-configuration", gateway.base_url))
        .send()
        .await
        .expect("discovery request should succeed")
        .json()
        .await
        .expect("discovery should be json");

    assert_eq!(discovery["issuer"], gateway.base_url);
    assert!(
        discovery["userinfo_endpoint"].as_str().is_some(),
        "userinfo_endpoint is required for OIDC"
    );
    assert!(
        discovery["subject_types_supported"]
            .as_array()
            .map(|a| a.iter().any(|v| v == "public"))
            .unwrap_or(false),
        "subject_types_supported must include public"
    );
    assert!(
        discovery["id_token_signing_alg_values_supported"]
            .as_array()
            .map(|a| a.iter().any(|v| v == "RS256"))
            .unwrap_or(false),
        "id_token_signing_alg_values_supported must include RS256"
    );
    assert!(
        discovery["scopes_supported"]
            .as_array()
            .map(|a| a.iter().any(|v| v == "openid"))
            .unwrap_or(false),
        "scopes_supported must include openid"
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn oidc_authorization_code_flow_returns_id_token() {
    let gateway = Gateway::start().await;
    let (client_id, token) = authorization_code_flow(&gateway).await;

    assert!(
        token["access_token"].as_str().is_some(),
        "access_token is required"
    );
    assert_eq!(
        token["token_type"].as_str().map(|s| s.to_ascii_lowercase()),
        Some("bearer".to_string())
    );
    let id_token = token["id_token"]
        .as_str()
        .expect("id_token is required for OIDC authorization_code");

    let claims = decode_jwt_payload(id_token);
    assert_eq!(claims["iss"], gateway.base_url, "id_token iss must match issuer");
    assert_eq!(
        claims["sub"], "conformance-user",
        "id_token sub must match the authenticated subject"
    );
    assert!(
        claims["aud"].as_array().map(|a| a.iter().any(|v| v == &client_id)).unwrap_or(false),
        "id_token aud must include the requesting client"
    );
    assert!(
        claims["exp"].as_u64().is_some(),
        "id_token must contain an exp claim"
    );
    assert!(
        claims["iat"].as_u64().is_some(),
        "id_token must contain an iat claim"
    );
    assert!(
        claims["nonce"].is_null(),
        "id_token must not contain a nonce when none was requested"
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be valid")
        .as_secs();
    assert!(
        claims["exp"].as_u64().expect("exp") > now,
        "id_token must not be expired"
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn oidc_userinfo_returns_claims_for_valid_token() {
    let gateway = Gateway::start().await;
    let (_client_id, token) = authorization_code_flow(&gateway).await;
    let access_token = token["access_token"].as_str().expect("access_token");

    let userinfo: serde_json::Value = gateway
        .http
        .get(format!("{}/oauth2/userinfo", gateway.base_url))
        .bearer_auth(access_token)
        .send()
        .await
        .expect("userinfo request should succeed")
        .json()
        .await
        .expect("userinfo should be json");

    assert_eq!(
        userinfo["sub"], "conformance-user",
        "userinfo sub must match the authenticated subject"
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn oidc_userinfo_rejects_missing_bearer() {
    let gateway = Gateway::start().await;

    let resp = gateway
        .http
        .get(format!("{}/oauth2/userinfo", gateway.base_url))
        .send()
        .await
        .expect("userinfo request should complete");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "userinfo must require a bearer token"
    );

    gateway.shutdown().await;
}

/// Perform a full OIDC authorization-code flow against Hydra through the gateway
/// and return `(client_id, token_response)`.
async fn authorization_code_flow(gateway: &Gateway) -> (String, serde_json::Value) {
    let redirect_uri = "http://127.0.0.1:9999/callback";
    let app = gateway
        .create_application(
            "oidc-auth-code-conformance",
            &[redirect_uri],
            &["authorization_code"],
            &["code"],
            &["openid", "profile"],
        )
        .await;
    let app_id = app["id"].as_str().expect("app id");
    let (client_id, client_secret) = gateway.rotate_secret(app_id).await;

    let no_redirect = reqwest::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("no-redirect client should build");

    // 1. Start an authorization request and capture the login challenge.
    let auth_resp = no_redirect
        .get(format!("{}/oauth2/auth", gateway.hydra_public_url))
        .query(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", redirect_uri),
            ("scope", "openid profile"),
            ("state", "conformance-state"),
        ])
        .send()
        .await
        .expect("authorize request should complete");

    assert!(
        auth_resp.status().is_redirection(),
        "authorize should redirect to login: {:?}",
        auth_resp.status()
    );
    let login_location = auth_resp
        .headers()
        .get("location")
        .and_then(|h| h.to_str().ok())
        .expect("login location header should exist");
    let login_challenge = extract_query_param(login_location, "login_challenge")
        .expect("login_challenge should be present");

    // 2. Accept the login request.
    let login_accept: serde_json::Value = no_redirect
        .put(format!("{}/admin/oauth2/auth/requests/login/accept", gateway.hydra_admin_url))
        .query(&[("login_challenge", &login_challenge)])
        .json(&json!({
            "subject": "conformance-user",
            "remember": false,
        }))
        .send()
        .await
        .expect("login accept request should succeed")
        .json()
        .await
        .expect("login accept should be json");
    let after_login = login_accept["redirect_to"]
        .as_str()
        .expect("login accept should return redirect_to");

    // 3. Follow the login redirect to obtain the consent challenge.
    // Hydra returns URLs using URLS_SELF_ISSUER (localhost:4444); rewrite them
    // to the mapped container address used by the harness.
    let after_login = resolve_hydra_url(after_login, &gateway.base_url, &gateway.hydra_public_url);
    let consent_resp = no_redirect
        .get(&after_login)
        .send()
        .await
        .expect("login redirect should complete");
    assert!(
        consent_resp.status().is_redirection(),
        "after login should redirect to consent: {:?}",
        consent_resp.status()
    );
    let consent_location = consent_resp
        .headers()
        .get("location")
        .and_then(|h| h.to_str().ok())
        .expect("consent location header should exist");
    let consent_location = resolve_hydra_url(consent_location, &gateway.base_url, &gateway.hydra_public_url);
    let consent_challenge = extract_query_param(&consent_location, "consent_challenge")
        .or_else(|| extract_query_param(&consent_location, "consent_verifier"))
        .expect("consent_challenge or consent_verifier should be present");

    // 4. Accept the consent request.
    let consent_accept: serde_json::Value = no_redirect
        .put(format!("{}/admin/oauth2/auth/requests/consent/accept", gateway.hydra_admin_url))
        .query(&[("consent_challenge", &consent_challenge)])
        .json(&json!({
            "grant_scope": ["openid", "profile"],
            "remember": false,
        }))
        .send()
        .await
        .expect("consent accept request should succeed")
        .json()
        .await
        .expect("consent accept should be json");
    let redirect_to = consent_accept["redirect_to"]
        .as_str()
        .expect("consent accept should return redirect_to");

    // 5. Follow the consent verifier redirect to obtain the final
    // authorization redirect containing the code.
    let redirect_to = resolve_hydra_url(redirect_to, &gateway.base_url, &gateway.hydra_public_url);
    let final_resp = no_redirect
        .get(&redirect_to)
        .send()
        .await
        .expect("consent verifier redirect should complete");
    assert!(
        final_resp.status().is_redirection(),
        "consent accept should redirect to client redirect_uri: {:?}",
        final_resp.status()
    );
    let final_location = final_resp
        .headers()
        .get("location")
        .and_then(|h| h.to_str().ok())
        .expect("final location header should exist");

    // 6. Extract the authorization code from the final redirect URI.
    let code = extract_query_param(final_location, "code").expect("redirect should contain code");
    let state = extract_query_param(final_location, "state").expect("redirect should contain state");
    assert_eq!(state, "conformance-state");

    // 6. Exchange the code at the gateway token endpoint.
    let token: serde_json::Value = gateway
        .http
        .post(format!("{}/oauth2/token", gateway.base_url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", redirect_uri),
            ("client_id", &client_id),
            ("client_secret", &client_secret),
        ])
        .send()
        .await
        .expect("token exchange should succeed")
        .json()
        .await
        .expect("token response should be json");

    (client_id, token)
}

fn extract_query_param(url: &str, key: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()?
        .query_pairs()
        .find_map(|(k, v)| if k == key { Some(v.into_owned()) } else { None })
}

fn resolve_hydra_url(url: &str, gateway_base_url: &str, hydra_public_url: &str) -> String {
    let url = url.replacen("http://localhost:4444", hydra_public_url, 1);
    url.replacen(gateway_base_url, hydra_public_url, 1)
}

fn decode_jwt_payload(token: &str) -> serde_json::Value {
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "id_token must be a JWT with three segments");
    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("id_token payload should be base64url encoded");
    serde_json::from_slice(&payload).expect("id_token payload should be valid JSON")
}
