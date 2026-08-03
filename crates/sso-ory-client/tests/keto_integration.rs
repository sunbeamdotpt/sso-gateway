// SSO-027: tests may unwrap/expect freely; the panic/default bans target production code.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods))]

use sso_ory_client::KetoClient;
use sso_ory_client::keto::TupleSubject;
use testcontainers::{ContainerAsync, GenericImage};

mod support;

/// One Keto container per test binary, shared by all tests: the support
/// harness removes every testcontainers-labelled container on first start,
/// so concurrently-started containers can be killed mid-test.
static KETO: tokio::sync::OnceCell<(ContainerAsync<GenericImage>, String, String)> =
    tokio::sync::OnceCell::const_new();

async fn keto_urls() -> (String, String) {
    let (_, read_url, write_url) = KETO
        .get_or_init(|| async { support::start_keto().await.expect("keto should start") })
        .await;
    (read_url.clone(), write_url.clone())
}

/// Both tests share one Keto container and one `app` namespace; concurrent
/// writes trip Keto's serialization ("concurrent update in another
/// session"), so run them one at a time.
static KETO_WRITE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn keto_relation_tuple_lifecycle() {
    let _guard = KETO_WRITE_LOCK.lock().await;
    let (read_url, write_url) = keto_urls().await;

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
        .create_relation_tuple("app", "doc-1", "read", TupleSubject::Id("alice"))
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
        .delete_relation_tuple("app", "doc-1", "read", TupleSubject::Id("alice"))
        .await
        .expect("delete tuple should succeed");
    assert!(
        !client
            .check_permission("app", "doc-1", "read", "alice")
            .await
            .expect("check should succeed")
    );
}

/// Subject-set tuples are traversed during checks: a user gains access by
/// belonging to a group that is the subject of another tuple. This is the
/// mechanism group-derived entitlements rely on.
#[tokio::test]
async fn keto_subject_set_tuple_is_traversed_by_check() {
    let _guard = KETO_WRITE_LOCK.lock().await;
    let (read_url, write_url) = keto_urls().await;

    let client = KetoClient::new(&read_url, &write_url).expect("client should build");

    // Members of team-ss can read doc-ss.
    let tuple = client
        .create_relation_tuple(
            "app",
            "doc-ss",
            "read",
            TupleSubject::Set {
                namespace: "app".into(),
                object: "team-ss".into(),
                relation: "member".into(),
            },
        )
        .await
        .expect("subject-set create should succeed");
    assert!(tuple.get("subject_id").is_none());
    assert_eq!(tuple["subject_set"]["object"], "team-ss");

    // Alice is a member of team-ss; Bob is not.
    client
        .create_relation_tuple("app", "team-ss", "member", TupleSubject::Id("alice-ss"))
        .await
        .expect("membership create should succeed");

    assert!(
        client
            .check_permission("app", "doc-ss", "read", "alice-ss")
            .await
            .expect("check should succeed"),
        "group-derived access should resolve through the subject set"
    );
    assert!(
        !client
            .check_permission("app", "doc-ss", "read", "bob")
            .await
            .expect("check should succeed")
    );

    // Removing the subject-set tuple revokes the derived access.
    client
        .delete_relation_tuple(
            "app",
            "doc-ss",
            "read",
            TupleSubject::Set {
                namespace: "app".into(),
                object: "team-ss".into(),
                relation: "member".into(),
            },
        )
        .await
        .expect("subject-set delete should succeed");
    assert!(
        !client
            .check_permission("app", "doc-ss", "read", "alice-ss")
            .await
            .expect("check should succeed")
    );
}
