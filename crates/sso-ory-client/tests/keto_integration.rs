use sso_ory_client::KetoClient;

mod support;

#[tokio::test]
async fn keto_relation_tuple_lifecycle() {
    let (_container, read_url, write_url) = support::start_keto().await.expect("keto should start");

    let client = KetoClient::new(&read_url, &write_url).expect("client should build");

    // Initially Alice has no access.
    assert!(
        !client
            .check_permission("app", "doc-1", "read", "alice")
            .await
            .expect("check should succeed")
    );

    // Grant Alice read access.
    let tuple = client
        .create_relation_tuple("app", "doc-1", "read", "alice")
        .await
        .expect("create tuple should succeed");
    assert_eq!(tuple["namespace"], "app");
    assert_eq!(tuple["object"], "doc-1");
    assert_eq!(tuple["relation"], "read");
    assert_eq!(tuple["subject_id"], "alice");

    assert!(
        client
            .check_permission("app", "doc-1", "read", "alice")
            .await
            .expect("check should succeed")
    );
    assert!(
        !client
            .check_permission("app", "doc-1", "read", "bob")
            .await
            .expect("check should succeed")
    );

    let expanded = client
        .expand("app", "doc-1", "read")
        .await
        .expect("expand should succeed");
    assert!(expanded["children"].is_array());

    // Revoke access.
    client
        .delete_relation_tuple("app", "doc-1", "read", "alice")
        .await
        .expect("delete tuple should succeed");
    assert!(
        !client
            .check_permission("app", "doc-1", "read", "alice")
            .await
            .expect("check should succeed")
    );
}
