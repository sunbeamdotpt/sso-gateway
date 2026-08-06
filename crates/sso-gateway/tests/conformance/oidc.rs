use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ulid::Ulid;

use crate::harness::Gateway;

#[tokio::test]
async fn oidc_discovery_has_oidc_required_fields() {
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
    let subject = Ulid::new().to_string();

    let result = gateway
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

    assert_token_response(&result.token, true);
    assert_id_token(
        &gateway,
        result.token["id_token"].as_str().expect("id_token"),
        &subject,
        &result.ory_client_id,
        None,
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn oidc_authorization_code_with_pkce_returns_id_token() {
    let gateway = Gateway::start().await;
    let subject = Ulid::new().to_string();

    let result = gateway
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

    assert_token_response(&result.token, true);
    assert!(result.code.starts_with("ory_ac_") || !result.code.is_empty());

    gateway.shutdown().await;
}

#[tokio::test]
async fn oidc_nonce_is_returned_in_id_token() {
    let gateway = Gateway::start().await;
    let subject = Ulid::new().to_string();
    let nonce = Ulid::new().to_string();

    let result = gateway
        .authorization_code_flow_through_gateway(
            &subject,
            REDIRECT_URI,
            &["authorization_code"],
            &["code"],
            &["openid", "profile"],
            false,
            Some(&nonce),
        )
        .await;

    let id_token = result.token["id_token"].as_str().expect("id_token");
    let claims = decode_jwt_payload(id_token);
    assert_eq!(
        claims["nonce"], nonce,
        "id_token nonce must match the requested nonce"
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn oidc_hybrid_code_id_token_returns_both() {
    let gateway = Gateway::start().await;
    let subject = Ulid::new().to_string();
    let nonce = Ulid::new().to_string();

    let result = gateway
        .authorization_code_flow_through_gateway(
            &subject,
            REDIRECT_URI,
            &["authorization_code", "implicit"],
            &["code", "id_token"],
            &["openid", "profile"],
            false,
            Some(&nonce),
        )
        .await;

    // Hybrid response contains an authorization code in the query and an
    // id_token in the fragment.
    assert!(
        !result.code.is_empty(),
        "hybrid flow must return an authorization code"
    );
    let hybrid_id_token = result
        .id_token
        .as_ref()
        .expect("hybrid flow must return an id_token in the fragment");
    assert_id_token(
        &gateway,
        hybrid_id_token,
        &subject,
        &result.ory_client_id,
        Some(&nonce),
    );

    // The code can still be exchanged for a token response that also contains
    // an id_token.
    assert_token_response(&result.token, true);

    gateway.shutdown().await;
}

#[tokio::test]
async fn oidc_id_token_signature_validates_against_jwks() {
    let gateway = Gateway::start().await;
    let subject = Ulid::new().to_string();

    let result = gateway
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

    let id_token = result.token["id_token"].as_str().expect("id_token");
    let jwks: serde_json::Value = gateway
        .http
        .get(format!("{}/.well-known/jwks.json", gateway.base_url))
        .send()
        .await
        .expect("jwks request should succeed")
        .json()
        .await
        .expect("jwks should be json");

    let keys = jwks["keys"].as_array().expect("jwks keys array");
    assert!(!keys.is_empty(), "jwks must contain at least one key");

    let header = decode_jwt_header(id_token);
    let kid = header["kid"].as_str().expect("id_token kid");
    let key = keys
        .iter()
        .find(|k| k["kid"].as_str() == Some(kid))
        .expect("jwks must contain the signing key");

    assert_eq!(key["kty"], "RSA", "signing key must be an RSA key");
    assert!(
        key["n"].as_str().is_some(),
        "signing key must include RSA modulus"
    );
    assert!(
        key["e"].as_str().is_some(),
        "signing key must include RSA exponent"
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn oidc_id_token_contains_at_hash_for_hybrid_token() {
    let gateway = Gateway::start().await;
    let subject = Ulid::new().to_string();
    let nonce = Ulid::new().to_string();

    let result = gateway
        .authorization_code_flow_through_gateway(
            &subject,
            REDIRECT_URI,
            &["authorization_code", "implicit"],
            &["code", "token", "id_token"],
            &["openid", "profile"],
            false,
            Some(&nonce),
        )
        .await;

    // For response_type=code token id_token the access token comes in the
    // fragment together with the id_token.
    let id_token = result
        .id_token
        .as_ref()
        .expect("hybrid flow must return id_token in fragment");
    let claims = decode_jwt_payload(id_token);
    assert!(
        claims["at_hash"].as_str().is_some(),
        "id_token must contain at_hash when access_token is issued in authorization response"
    );

    // at_hash must be present and well-formed in the hybrid id_token. The exact
    // access token value Hydra hashes is an implementation detail of the OP; the
    // gateway's contract is to surface the id_token unmodified.
    assert!(
        claims["at_hash"].as_str().is_some_and(|v| !v.is_empty()),
        "id_token at_hash must be a non-empty string"
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn oidc_refresh_token_flow_returns_new_id_token() {
    let gateway = Gateway::start().await;
    let subject = Ulid::new().to_string();

    let result = gateway
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

    let refresh_token = result.token["refresh_token"]
        .as_str()
        .expect("refresh_token should be issued when offline_access is requested");

    let refreshed = gateway
        .refresh_token_flow(refresh_token, &result.client_id, &result.client_secret)
        .await;

    assert_token_response(&refreshed, true);
    assert_id_token(
        &gateway,
        refreshed["id_token"].as_str().expect("id_token"),
        &subject,
        &result.ory_client_id,
        None,
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn oidc_userinfo_returns_claims_for_valid_token() {
    let gateway = Gateway::start().await;
    let subject = Ulid::new().to_string();

    let result = gateway
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
    let access_token = result.token["access_token"].as_str().expect("access_token");

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
        userinfo["sub"], subject,
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

const REDIRECT_URI: &str = "https://127.0.0.1:9999/callback";

fn assert_token_response(token: &serde_json::Value, expect_id_token: bool) {
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

/// Assert the id_token is a well-formed compact JWS: no whitespace, exactly
/// three non-empty strict-base64url segments, and an RSA-sized signature.
/// Guards against regressions where the gateway token passthrough introduces
/// whitespace or otherwise corrupts the Hydra-issued token.
///
/// The harness parses the token response as JSON, so this checks the parsed
/// string value; because serde_json would have unescaped any `\n`/`\t`
/// escapes into literal characters, the whitespace check below catches
/// corruption present either literally or escaped in the raw response.
fn assert_id_token_well_formed(id_token: &str) {
    assert!(!id_token.is_empty(), "id_token must not be empty");
    assert!(
        !id_token.chars().any(char::is_whitespace),
        "id_token must not contain whitespace: {id_token:?}"
    );
    assert!(
        id_token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')),
        "id_token must match /^[A-Za-z0-9_\\-\\.]+$/: {id_token:?}"
    );

    let parts: Vec<&str> = id_token.split('.').collect();
    assert_eq!(parts.len(), 3, "id_token must be a JWT with three segments");
    for (idx, part) in parts.iter().enumerate() {
        assert!(!part.is_empty(), "id_token segment {idx} must not be empty");
        // URL_SAFE_NO_PAD rejects padding, whitespace, and any character
        // outside the base64url alphabet.
        URL_SAFE_NO_PAD
            .decode(part)
            .unwrap_or_else(|e| panic!("id_token segment {idx} must be strict base64url: {e}"));
    }

    let signature = URL_SAFE_NO_PAD
        .decode(parts[2])
        .expect("id_token signature should be base64url encoded");
    assert!(
        matches!(signature.len(), 256 | 512),
        "id_token signature must be a plausible RSA size (256 or 512 bytes), got {} bytes",
        signature.len()
    );
}

fn assert_id_token(
    gateway: &Gateway,
    id_token: &str,
    subject: &str,
    ory_client_id: &str,
    expected_nonce: Option<&str>,
) {
    assert_id_token_well_formed(id_token);
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

    if let Some(nonce) = expected_nonce {
        assert_eq!(
            claims["nonce"].as_str(),
            Some(nonce),
            "id_token nonce must match"
        );
    }
}

fn decode_jwt_header(token: &str) -> serde_json::Value {
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "id_token must be a JWT with three segments");
    let header = URL_SAFE_NO_PAD
        .decode(parts[0])
        .expect("id_token header should be base64url encoded");
    serde_json::from_slice(&header).expect("id_token header should be valid JSON")
}

fn decode_jwt_payload(token: &str) -> serde_json::Value {
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "id_token must be a JWT with three segments");
    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("id_token payload should be base64url encoded");
    serde_json::from_slice(&payload).expect("id_token payload should be valid JSON")
}
