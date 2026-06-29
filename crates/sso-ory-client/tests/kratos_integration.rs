use serde_json::json;
use sso_ory_client::KratosClient;

mod support;

#[tokio::test]
async fn kratos_identity_lifecycle() {
    let (_container, admin_url, _public_url) =
        support::start_kratos().await.expect("kratos should start");

    let client = KratosClient::new(&admin_url).expect("client should build");

    let created = client
        .create_identity(json!({
            "schema_id": "default",
            "traits": { "email": "alice@example.com" }
        }))
        .await
        .expect("create identity should succeed");

    let id = created["id"].as_str().expect("identity id should exist");
    assert_eq!(created["traits"]["email"], "alice@example.com");

    let fetched = client
        .get_identity(id)
        .await
        .expect("get identity should succeed");
    assert_eq!(fetched["id"], id);

    let updated = client
        .update_identity(
            id,
            json!({
                "schema_id": "default",
                "traits": { "email": "alice-updated@example.com" }
            }),
        )
        .await
        .expect("update identity should succeed");
    assert_eq!(updated["traits"]["email"], "alice-updated@example.com");

    client
        .delete_identity(id)
        .await
        .expect("delete identity should succeed");
}
