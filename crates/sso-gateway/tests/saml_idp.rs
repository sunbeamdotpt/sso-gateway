use std::sync::Arc;

use gamlastan::bindings::RelayState;
use gamlastan::bindings::redirect::{RedirectEncodeParams, redirect_encode};
use gamlastan::core::assertion::issuer::IssuerRef;
use gamlastan::core::assertion::name_id::NameIdPolicyRef;
use gamlastan::core::constants::{BINDING_HTTP_POST, NAMEID_EMAIL};
use gamlastan::core::identifiers::SamlVersion;
use gamlastan::core::protocol::request::{AuthnRequestRef, RequestBaseRef};
use gamlastan::xml::SamlSerialize;
use sso_gateway::db::{SamlIdpKeyRepo, SamlSpClientRepo, bootstrap_system_tenant, create_pool};
use sso_gateway::services::handlers::saml_idp::{SamlIdpState, router as saml_idp_router};
use sso_ory_client::kratos::KratosClient;
use sunbeam_g2v::server::axum::bind_random_port;

mod support;

const SIG_ALG_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

fn build_authn_request_xml(id: &str, issuer: &str, destination: &str, acs_url: &str) -> String {
    let now = chrono::Utc::now();
    let request = AuthnRequestRef {
        base: RequestBaseRef {
            id,
            version: SamlVersion::V2_0,
            issue_instant: now,
            destination: Some(destination),
            consent: None,
            issuer: Some(IssuerRef {
                value: issuer,
                format: None,
                name_qualifier: None,
                sp_name_qualifier: None,
            }),
            has_signature: false,
        },
        subject: None,
        name_id_policy: Some(NameIdPolicyRef {
            format: Some(NAMEID_EMAIL),
            sp_name_qualifier: None,
            allow_create: true,
        }),
        conditions: None,
        requested_authn_context: None,
        scoping: None,
        force_authn: Some(false),
        is_passive: Some(false),
        assertion_consumer_service_index: None,
        assertion_consumer_service_url: Some(acs_url),
        protocol_binding: Some(BINDING_HTTP_POST),
        attribute_consuming_service_index: None,
        provider_name: Some("Test SP"),
        extensions: None,
    }
    .to_owned();

    request.to_xml_string().expect("serialize AuthnRequest")
}

fn sp_signer() -> gamlastan::crypto::SamlSigner {
    let key_pem = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/saml-test-key.pem"
    ))
    .expect("read saml test key");
    let key_manager =
        gamlastan::crypto::keys::build_idp_keys_manager(&key_pem).expect("load saml test key");
    gamlastan::crypto::SamlSigner::new(key_manager)
}

fn encode_redirect(
    destination: &str,
    request_xml: &str,
    signer: Option<&gamlastan::crypto::SamlSigner>,
    relay_state: &str,
) -> String {
    let rs = RelayState::new(relay_state).expect("valid relay state");
    let params = RedirectEncodeParams {
        saml_xml: request_xml.as_bytes(),
        is_request: true,
        destination,
        relay_state: Some(&rs),
        signer: signer.map(|s| (s, SIG_ALG_RSA_SHA256)),
    };
    redirect_encode(&params).expect("encode redirect")
}

async fn create_kratos_identity_and_session(public_url: &str, email: &str) -> (String, String) {
    let client = reqwest::Client::new();

    let flow: serde_json::Value = client
        .get(format!("{public_url}/self-service/registration/api"))
        .header("Accept", "application/json")
        .send()
        .await
        .expect("create registration flow request should succeed")
        .json()
        .await
        .expect("registration flow response should be json");

    let flow_id = flow["id"].as_str().expect("flow id should exist");
    let csrf_token = flow["ui"]["nodes"]
        .as_array()
        .and_then(|nodes| {
            nodes.iter().find_map(|n| {
                if n["attributes"]["name"] == "csrf_token" {
                    n["attributes"]["value"].as_str()
                } else {
                    None
                }
            })
        })
        .unwrap_or("");

    let mut body = serde_json::json!({
        "method": "password",
        "password": "TestPass123!",
        "traits": { "email": email }
    });
    if !csrf_token.is_empty() {
        body["csrf_token"] = serde_json::json!(csrf_token);
    }

    let resp = client
        .post(format!("{public_url}/self-service/registration"))
        .query(&[("flow", flow_id)])
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .expect("submit registration request should succeed");

    let status = resp.status();
    let text = resp
        .text()
        .await
        .expect("registration submit body should be text");
    assert!(
        status.is_success(),
        "registration submit failed: {status} {text}"
    );

    let result: serde_json::Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("registration submit should be json: {e}\n{text}"));

    let session_token = result["session_token"]
        .as_str()
        .expect("session_token should exist")
        .to_string();
    let identity_id = result["identity"]["id"]
        .as_str()
        .expect("identity id should exist")
        .to_string();

    (identity_id, session_token)
}

async fn start_idp_server(
    database_url: &str,
    kratos_admin_url: &str,
    kratos_public_url: &str,
) -> (String, SamlIdpState, String, String) {
    let pool = create_pool(database_url, false)
        .await
        .expect("database pool should be created");

    let system_tenant_ulid = ulid::Ulid::new().to_string();
    bootstrap_system_tenant(&pool, &system_tenant_ulid)
        .await
        .expect("system tenant should bootstrap");

    let key_pem = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/saml-test-key.pem"
    ))
    .expect("read saml test key");
    let cert_pem = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/saml-test-cert.pem"
    ))
    .expect("read saml test cert");

    let idp_keys = SamlIdpKeyRepo::with_encryption_key(pool.clone(), vec![0u8; 32]);
    idp_keys
        .create(&system_tenant_ulid, "key-1", &key_pem, &cert_pem, true)
        .await
        .expect("idp key should be created");

    let sp_clients = SamlSpClientRepo::new(pool);

    let kratos = Arc::new(
        KratosClient::new_with_public(kratos_admin_url, kratos_public_url)
            .expect("kratos client should build"),
    );

    let idp_entity_id = "https://gateway.example.com/saml/idp".to_string();

    let state = SamlIdpState::new(kratos, idp_keys, sp_clients, idp_entity_id.clone());

    (system_tenant_ulid, state, idp_entity_id, cert_pem)
}

#[tokio::test]
async fn saml_idp_sso_round_trip_unsigned_request() {
    let (_pg, database_url) = support::start_postgres()
        .await
        .expect("postgres should start");
    let (_kratos, kratos_admin_url, kratos_public_url) =
        support::start_kratos().await.expect("kratos should start");

    let (tenant_id, state, _idp_entity_id, _idp_cert) =
        start_idp_server(&database_url, &kratos_admin_url, &kratos_public_url).await;

    let sp_clients = SamlSpClientRepo::new(
        sso_gateway::db::create_pool(&database_url, false)
            .await
            .expect("pool"),
    );
    let sp_client = sp_clients
        .create(
            &tenant_id,
            "https://sp.example.com",
            "https://sp.example.com/acs",
            None,
            false,
            Some(NAMEID_EMAIL),
        )
        .await
        .expect("sp client should be created");

    let (_identity_id, session_token) =
        create_kratos_identity_and_session(&kratos_public_url, "alice@example.com").await;

    let (listener, addr) = bind_random_port("127.0.0.1")
        .await
        .expect("random port should bind");

    let saml_destination = format!("http://{addr}/saml/sso");
    let app = saml_idp_router(Arc::new(
        state.with_sso_endpoint_url(saml_destination.clone()),
    ));

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("server should run");
    });

    let destination = format!("http://{addr}/saml/sso?provider_id={}", sp_client.id);
    let request_xml = build_authn_request_xml(
        "_req_unsigned_1",
        &sp_client.entity_id,
        &saml_destination,
        &sp_client.acs_url,
    );
    let redirect_url = encode_redirect(&destination, &request_xml, None, "after-login");

    let client = reqwest::Client::new();
    let resp = client
        .get(&redirect_url)
        .header("X-Session-Token", &session_token)
        .send()
        .await
        .expect("sso request should succeed");

    assert!(
        resp.status().is_success(),
        "sso endpoint failed: {}",
        resp.text().await.unwrap_or_default()
    );

    let body = resp.text().await.expect("sso body should be text");
    assert!(body.contains(r#"<form method="post" action="https://sp.example.com/acs">"#));
    assert!(body.contains(r#"<input type="hidden" name="SAMLResponse""#));
    assert!(body.contains(r#"<input type="hidden" name="RelayState" value="after-login"/>"#));

    let _ = shutdown_tx.send(());
    handle.await.expect("server task should finish");
}

#[tokio::test]
async fn saml_idp_sso_signed_request_verifies_signature() {
    let (_pg, database_url) = support::start_postgres()
        .await
        .expect("postgres should start");
    let (_kratos, kratos_admin_url, kratos_public_url) =
        support::start_kratos().await.expect("kratos should start");

    let (tenant_id, state, _idp_entity_id, _idp_cert) =
        start_idp_server(&database_url, &kratos_admin_url, &kratos_public_url).await;

    let sp_cert = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/saml-test-cert.pem"
    ))
    .expect("read sp cert");

    let sp_clients = SamlSpClientRepo::new(
        sso_gateway::db::create_pool(&database_url, false)
            .await
            .expect("pool"),
    );
    let sp_client = sp_clients
        .create(
            &tenant_id,
            "https://sp.example.com",
            "https://sp.example.com/acs",
            Some(&sp_cert),
            true,
            Some(NAMEID_EMAIL),
        )
        .await
        .expect("sp client should be created");

    let (_identity_id, session_token) =
        create_kratos_identity_and_session(&kratos_public_url, "bob@example.com").await;

    let (listener, addr) = bind_random_port("127.0.0.1")
        .await
        .expect("random port should bind");

    let saml_destination = format!("http://{addr}/saml/sso");
    let app = saml_idp_router(Arc::new(
        state.with_sso_endpoint_url(saml_destination.clone()),
    ));

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("server should run");
    });

    let signer = sp_signer();
    let destination = format!("http://{addr}/saml/sso?provider_id={}", sp_client.id);
    let request_xml = build_authn_request_xml(
        "_req_signed_1",
        &sp_client.entity_id,
        &saml_destination,
        &sp_client.acs_url,
    );
    let redirect_url = encode_redirect(&destination, &request_xml, Some(&signer), "signed-state");

    let client = reqwest::Client::new();
    let resp = client
        .get(&redirect_url)
        .header("X-Session-Token", &session_token)
        .send()
        .await
        .expect("sso request should succeed");

    assert!(
        resp.status().is_success(),
        "signed sso endpoint failed: {}",
        resp.text().await.unwrap_or_default()
    );

    let body = resp.text().await.expect("sso body should be text");
    assert!(body.contains("SAMLResponse"));
    assert!(body.contains("signed-state"));

    let _ = shutdown_tx.send(());
    handle.await.expect("server task should finish");
}

#[tokio::test]
async fn saml_idp_sso_rejects_issuer_mismatch() {
    let (_pg, database_url) = support::start_postgres()
        .await
        .expect("postgres should start");
    let (_kratos, kratos_admin_url, kratos_public_url) =
        support::start_kratos().await.expect("kratos should start");

    let (tenant_id, state, _idp_entity_id, _idp_cert) =
        start_idp_server(&database_url, &kratos_admin_url, &kratos_public_url).await;

    let sp_clients = SamlSpClientRepo::new(
        sso_gateway::db::create_pool(&database_url, false)
            .await
            .expect("pool"),
    );
    let sp_client = sp_clients
        .create(
            &tenant_id,
            "https://sp.example.com",
            "https://sp.example.com/acs",
            None,
            false,
            Some(NAMEID_EMAIL),
        )
        .await
        .expect("sp client should be created");

    let (_identity_id, session_token) =
        create_kratos_identity_and_session(&kratos_public_url, "charlie@example.com").await;

    let (listener, addr) = bind_random_port("127.0.0.1")
        .await
        .expect("random port should bind");

    let saml_destination = format!("http://{addr}/saml/sso");
    let app = saml_idp_router(Arc::new(
        state.with_sso_endpoint_url(saml_destination.clone()),
    ));

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("server should run");
    });

    let destination = format!("http://{addr}/saml/sso?provider_id={}", sp_client.id);
    let request_xml = build_authn_request_xml(
        "_req_issuer_1",
        "https://evil.example.com",
        &saml_destination,
        &sp_client.acs_url,
    );
    let redirect_url = encode_redirect(&destination, &request_xml, None, "state");

    let client = reqwest::Client::new();
    let resp = client
        .get(&redirect_url)
        .header("X-Session-Token", &session_token)
        .send()
        .await
        .expect("sso request should succeed");

    assert_eq!(resp.status(), 400);
    let body = resp.text().await.expect("error body should be text");
    assert!(body.contains("issuer mismatch"));

    let _ = shutdown_tx.send(());
    handle.await.expect("server task should finish");
}

#[tokio::test]
async fn saml_idp_sso_rejects_missing_session() {
    let (_pg, database_url) = support::start_postgres()
        .await
        .expect("postgres should start");
    let (_kratos, kratos_admin_url, kratos_public_url) =
        support::start_kratos().await.expect("kratos should start");

    let (tenant_id, state, _idp_entity_id, _idp_cert) =
        start_idp_server(&database_url, &kratos_admin_url, &kratos_public_url).await;

    let sp_clients = SamlSpClientRepo::new(
        sso_gateway::db::create_pool(&database_url, false)
            .await
            .expect("pool"),
    );
    let sp_client = sp_clients
        .create(
            &tenant_id,
            "https://sp.example.com",
            "https://sp.example.com/acs",
            None,
            false,
            Some(NAMEID_EMAIL),
        )
        .await
        .expect("sp client should be created");

    let (listener, addr) = bind_random_port("127.0.0.1")
        .await
        .expect("random port should bind");

    let saml_destination = format!("http://{addr}/saml/sso");
    let app = saml_idp_router(Arc::new(
        state.with_sso_endpoint_url(saml_destination.clone()),
    ));

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("server should run");
    });

    let destination = format!("http://{addr}/saml/sso?provider_id={}", sp_client.id);
    let request_xml = build_authn_request_xml(
        "_req_session_1",
        &sp_client.entity_id,
        &saml_destination,
        &sp_client.acs_url,
    );
    let redirect_url = encode_redirect(&destination, &request_xml, None, "state");

    let client = reqwest::Client::new();
    let resp = client
        .get(&redirect_url)
        .send()
        .await
        .expect("sso request should succeed");

    assert_eq!(resp.status(), 401);

    let _ = shutdown_tx.send(());
    handle.await.expect("server task should finish");
}

#[tokio::test]
async fn saml_idp_sso_rejects_signed_request_without_sp_certificate() {
    let (_pg, database_url) = support::start_postgres()
        .await
        .expect("postgres should start");
    let (_kratos, kratos_admin_url, kratos_public_url) =
        support::start_kratos().await.expect("kratos should start");

    let (tenant_id, state, _idp_entity_id, _idp_cert) =
        start_idp_server(&database_url, &kratos_admin_url, &kratos_public_url).await;

    let sp_clients = SamlSpClientRepo::new(
        sso_gateway::db::create_pool(&database_url, false)
            .await
            .expect("pool"),
    );
    let sp_client = sp_clients
        .create(
            &tenant_id,
            "https://sp.example.com",
            "https://sp.example.com/acs",
            None,
            true,
            Some(NAMEID_EMAIL),
        )
        .await
        .expect("sp client should be created");

    let (_identity_id, session_token) =
        create_kratos_identity_and_session(&kratos_public_url, "dave@example.com").await;

    let (listener, addr) = bind_random_port("127.0.0.1")
        .await
        .expect("random port should bind");

    let saml_destination = format!("http://{addr}/saml/sso");
    let app = saml_idp_router(Arc::new(
        state.with_sso_endpoint_url(saml_destination.clone()),
    ));

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("server should run");
    });

    let signer = sp_signer();
    let destination = format!("http://{addr}/saml/sso?provider_id={}", sp_client.id);
    let request_xml = build_authn_request_xml(
        "_req_no_cert_1",
        &sp_client.entity_id,
        &saml_destination,
        &sp_client.acs_url,
    );
    let redirect_url = encode_redirect(&destination, &request_xml, Some(&signer), "state");

    let client = reqwest::Client::new();
    let resp = client
        .get(&redirect_url)
        .header("X-Session-Token", &session_token)
        .send()
        .await
        .expect("sso request should complete");

    assert_eq!(resp.status(), 400);
    let body = resp.text().await.expect("error body should be text");
    assert!(body.contains("signed authn request required but no sp certificate configured"));

    let _ = shutdown_tx.send(());
    handle.await.expect("server task should finish");
}

#[tokio::test]
async fn saml_idp_sso_rejects_invalid_signature() {
    let (_pg, database_url) = support::start_postgres()
        .await
        .expect("postgres should start");
    let (_kratos, kratos_admin_url, kratos_public_url) =
        support::start_kratos().await.expect("kratos should start");

    let (tenant_id, state, _idp_entity_id, _idp_cert) =
        start_idp_server(&database_url, &kratos_admin_url, &kratos_public_url).await;

    let other_cert_pem = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/saml-other-cert.pem"
    ))
    .expect("read cert");

    let sp_clients = SamlSpClientRepo::new(
        sso_gateway::db::create_pool(&database_url, false)
            .await
            .expect("pool"),
    );
    let sp_client = sp_clients
        .create(
            &tenant_id,
            "https://sp.example.com",
            "https://sp.example.com/acs",
            Some(&other_cert_pem),
            true,
            Some(NAMEID_EMAIL),
        )
        .await
        .expect("sp client should be created");

    let (_identity_id, session_token) =
        create_kratos_identity_and_session(&kratos_public_url, "eve@example.com").await;

    let (listener, addr) = bind_random_port("127.0.0.1")
        .await
        .expect("random port should bind");

    let saml_destination = format!("http://{addr}/saml/sso");
    let app = saml_idp_router(Arc::new(
        state.with_sso_endpoint_url(saml_destination.clone()),
    ));

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("server should run");
    });

    // Sign with the fixture key; the IdP trusts a different certificate, so verification fails.
    let signer = sp_signer();
    let destination = format!("http://{addr}/saml/sso?provider_id={}", sp_client.id);
    let request_xml = build_authn_request_xml(
        "_req_bad_sig_1",
        &sp_client.entity_id,
        &saml_destination,
        &sp_client.acs_url,
    );
    let redirect_url = encode_redirect(&destination, &request_xml, Some(&signer), "state");

    let client = reqwest::Client::new();
    let resp = client
        .get(&redirect_url)
        .header("X-Session-Token", &session_token)
        .send()
        .await
        .expect("sso request should complete");

    assert_eq!(resp.status(), 400);
    let body = resp.text().await.expect("error body should be text");
    assert!(body.contains("invalid authn request signature"));

    let _ = shutdown_tx.send(());
    handle.await.expect("server task should finish");
}
