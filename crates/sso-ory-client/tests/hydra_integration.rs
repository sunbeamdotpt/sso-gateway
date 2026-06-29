use serde_json::json;
use sso_ory_client::HydraClient;

mod support;

#[tokio::test]
async fn hydra_client_credentials_and_introspection() {
    let (_container, admin_url, public_url) =
        support::start_hydra().await.expect("hydra should start");

    let client = HydraClient::new(&admin_url, &public_url).expect("client should build");

    // Create an OAuth2 client that can use client credentials.
    let created = client
        .create_oauth2_client(json!({
            "client_name": "test-client",
            "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": "client_secret_basic",
            "scope": "openid"
        }))
        .await
        .expect("create client should succeed");

    let client_id = created["client_id"]
        .as_str()
        .expect("client_id should exist");
    let client_secret = created["client_secret"]
        .as_str()
        .expect("client_secret should exist");

    // Fetch the same client back.
    let fetched = client
        .get_oauth2_client(client_id)
        .await
        .expect("get client should succeed");
    assert_eq!(fetched["client_id"], client_id);

    // Obtain a token using the client credentials grant.
    let token_response: serde_json::Value = reqwest::Client::new()
        .post(format!("{public_url}/oauth2/token"))
        .basic_auth(client_id, Some(client_secret))
        .form(&[("grant_type", "client_credentials"), ("scope", "openid")])
        .send()
        .await
        .expect("token request should send")
        .json()
        .await
        .expect("token response should be json");

    let access_token = token_response["access_token"]
        .as_str()
        .expect("access_token should exist");

    // Introspect the token.
    let introspection = client
        .introspect_token(access_token)
        .await
        .expect("introspection should succeed");
    assert_eq!(introspection["active"], true);
    assert_eq!(introspection["client_id"], client_id);

    // Delete the client.
    client
        .delete_oauth2_client(client_id)
        .await
        .expect("delete client should succeed");
}
