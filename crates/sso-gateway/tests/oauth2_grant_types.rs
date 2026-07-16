use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ulid::Ulid;

#[path = "conformance/harness.rs"]
mod harness;

use harness::{AuthorizationFlowResult, Gateway};

const REDIRECT_URI: &str = "https://127.0.0.1:9999/callback";

#[tokio::test]
async fn authorization_code_flow_through_gateway_returns_tokens() {
    let gateway = Gateway::start().await;
    let subject = Ulid::new().to_string();

    let AuthorizationFlowResult {
        ory_client_id,
        token,
        ..
    } = gateway
        .authorization_code_flow_through_gateway(
            &subject,
            REDIRECT_URI,
            &["authorization_code"],
            &["code"],
            &["openid", "profile"],
            false,
            None,
        )
        .await;

    assert_token_response(&gateway, &token, true);
    assert_id_token(&gateway, &token, &subject, &ory_client_id);

    gateway.shutdown().await;
}

#[tokio::test]
async fn authorization_code_with_pkce_s256_returns_tokens() {
    let gateway = Gateway::start().await;
    let subject = Ulid::new().to_string();

    let AuthorizationFlowResult { token, .. } = gateway
        .authorization_code_flow_through_gateway(
            &subject,
            REDIRECT_URI,
            &["authorization_code"],
            &["code"],
            &["openid", "profile"],
            true,
            None,
        )
        .await;

    assert_token_response(&gateway, &token, true);

    gateway.shutdown().await;
}

#[tokio::test]
async fn refresh_token_flow_returns_new_access_token() {
    let gateway = Gateway::start().await;
    let subject = Ulid::new().to_string();

    let AuthorizationFlowResult {
        client_id,
        client_secret,
        token,
        ..
    } = gateway
        .authorization_code_flow_through_gateway(
            &subject,
            REDIRECT_URI,
            &["authorization_code", "refresh_token"],
            &["code"],
            &["openid", "offline_access"],
            false,
            None,
        )
        .await;

    let refresh_token = token["refresh_token"]
        .as_str()
        .expect("refresh_token should be issued when offline_access is requested");

    let refreshed = gateway
        .refresh_token_flow(refresh_token, &client_id, &client_secret)
        .await;

    assert!(
        refreshed["access_token"].as_str().is_some(),
        "refresh grant must issue a new access_token"
    );
    assert_eq!(
        refreshed["token_type"].as_str().map(|s| s.to_ascii_lowercase()),
        Some("bearer".to_string())
    );
    assert!(
        refreshed["expires_in"].as_u64().is_some(),
        "refresh grant must include expires_in"
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn implicit_flow_returns_access_token_in_fragment() {
    let gateway = Gateway::start().await;
    let subject = Ulid::new().to_string();

    let AuthorizationFlowResult { token, .. } = gateway
        .authorization_code_flow_through_gateway(
            &subject,
            REDIRECT_URI,
            &["implicit"],
            &["token"],
            &["openid", "profile"],
            false,
            None,
        )
        .await;

    assert!(
        token["access_token"].as_str().is_some(),
        "implicit flow must return access_token"
    );
    assert_eq!(
        token["token_type"].as_str().map(|s| s.to_ascii_lowercase()),
        Some("bearer".to_string())
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn client_credentials_with_client_secret_basic_returns_token() {
    let gateway = Gateway::start().await;
    let app = gateway
        .create_application_with_auth(
            "oauth2-cc-basic",
            &[REDIRECT_URI],
            &["client_credentials"],
            &["token"],
            &["openid"],
            "client_secret_basic",
        )
        .await;
    let app_id = app["id"].as_str().expect("app id");
    let (client_id, client_secret) = gateway.rotate_secret(app_id).await;

    let token: serde_json::Value = gateway
        .http
        .post(format!("{}/oauth2/token", gateway.base_url))
        .basic_auth(&client_id, Some(&client_secret))
        .form(&[
            ("grant_type", "client_credentials"),
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
async fn token_endpoint_rejects_invalid_requests() {
    let gateway = Gateway::start().await;
    let subject = Ulid::new().to_string();

    let AuthorizationFlowResult {
        code,
        client_id,
        client_secret,
        ..
    } = gateway
        .authorization_code_flow_through_gateway(
            &subject,
            REDIRECT_URI,
            &["authorization_code"],
            &["code"],
            &["openid", "profile"],
            false,
            None,
        )
        .await;

    // Invalid authorization code.
    let resp = gateway
        .http
        .post(format!("{}/oauth2/token", gateway.base_url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", "not-a-real-code"),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
        ])
        .send()
        .await
        .expect("token request should complete");
    assert!(
        resp.status().is_client_error(),
        "invalid code must be rejected: {:?}",
        resp.status()
    );

    // Missing redirect_uri.
    let resp = gateway
        .http
        .post(format!("{}/oauth2/token", gateway.base_url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
        ])
        .send()
        .await
        .expect("token request should complete");
    assert!(
        resp.status().is_client_error(),
        "missing redirect_uri must be rejected: {:?}",
        resp.status()
    );

    // Wrong client_secret.
    let resp = gateway
        .http
        .post(format!("{}/oauth2/token", gateway.base_url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", client_id.as_str()),
            ("client_secret", "not-the-secret"),
        ])
        .send()
        .await
        .expect("token request should complete");
    assert!(
        resp.status().is_client_error(),
        "wrong client_secret must be rejected: {:?}",
        resp.status()
    );

    // Reused authorization code.
    let resp = gateway
        .http
        .post(format!("{}/oauth2/token", gateway.base_url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
        ])
        .send()
        .await
        .expect("token request should complete");
    assert!(
        resp.status().is_client_error(),
        "reused code must be rejected: {:?}",
        resp.status()
    );

    // Invalid refresh_token grant.
    let resp = gateway
        .http
        .post(format!("{}/oauth2/token", gateway.base_url))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", "not-a-real-token"),
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
        ])
        .send()
        .await
        .expect("token request should complete");
    assert!(
        resp.status().is_client_error(),
        "invalid refresh_token must be rejected: {:?}",
        resp.status()
    );

    // Unknown client_id.
    let resp = gateway
        .http
        .post(format!("{}/oauth2/token", gateway.base_url))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "unknown-client"),
            ("client_secret", "secret"),
            ("scope", "openid"),
        ])
        .send()
        .await
        .expect("token request should complete");
    assert!(
        resp.status().is_client_error(),
        "unknown client_id must be rejected: {:?}",
        resp.status()
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn userinfo_returns_claims_after_authorization_code_flow() {
    let gateway = Gateway::start().await;
    let subject = Ulid::new().to_string();

    let AuthorizationFlowResult { token, .. } = gateway
        .authorization_code_flow_through_gateway(
            &subject,
            REDIRECT_URI,
            &["authorization_code"],
            &["code"],
            &["openid", "profile"],
            false,
            None,
        )
        .await;
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

    // The gateway has no Kratos mapping for the synthetic test subject, so the
    // userinfo endpoint falls back to the raw Hydra subject.
    assert_eq!(
        userinfo["sub"], subject,
        "userinfo sub must match the authenticated subject"
    );

    gateway.shutdown().await;
}

fn assert_token_response(_gateway: &Gateway, token: &serde_json::Value, expect_id_token: bool) {
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
    if expect_id_token {
        assert!(
            token["id_token"].as_str().is_some(),
            "id_token is required for OIDC flows"
        );
    }
}

fn assert_id_token(gateway: &Gateway, token: &serde_json::Value, subject: &str, ory_client_id: &str) {
    let id_token = token["id_token"].as_str().expect("id_token");
    let claims = decode_jwt_payload(id_token);

    assert_eq!(
        claims["iss"], gateway.base_url,
        "id_token iss must match issuer"
    );
    assert_eq!(
        claims["sub"], subject,
        "id_token sub must match the authenticated subject"
    );
    assert!(
        claims["aud"]
            .as_array()
            .map(|a| a.iter().any(|v| v == ory_client_id))
            .unwrap_or(false),
        "id_token aud must include the Hydra client id used for authorization"
    );
    assert!(
        claims["exp"].as_u64().is_some(),
        "id_token must contain an exp claim"
    );
    assert!(
        claims["iat"].as_u64().is_some(),
        "id_token must contain an iat claim"
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be valid")
        .as_secs();
    assert!(
        claims["exp"].as_u64().expect("exp") > now,
        "id_token must not be expired"
    );
}

#[tokio::test]
async fn device_code_flow_returns_tokens() {
    let gateway = Gateway::start().await;
    let subject = Ulid::new().to_string();

    let token = gateway.device_code_flow(&subject).await;

    assert_token_response(&gateway, &token, true);

    gateway.shutdown().await;
}

fn decode_jwt_payload(token: &str) -> serde_json::Value {
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "id_token must be a JWT with three segments");
    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("id_token payload should be base64url encoded");
    serde_json::from_slice(&payload).expect("id_token payload should be valid JSON")
}
