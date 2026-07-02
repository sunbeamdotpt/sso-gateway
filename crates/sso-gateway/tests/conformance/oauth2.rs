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
