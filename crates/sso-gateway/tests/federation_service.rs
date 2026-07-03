use std::sync::Arc;

use axum::{Extension, middleware::from_fn};
use connectrpc::Router as ConnectRouter;
use gamlastan::security::InMemoryReplayCache;
use serde_json::json;
use sso_gateway::{
    db::{
        IdMappingRepo, IdMappingStore, IdentitySchemaRepo, LoginStateRepo, SamlIdentityMappingRepo,
        SamlIdpKeyRepo, SamlProviderRepo, SamlReplayCache, SamlReplayCacheTrait, SamlRequestRepo,
        TenantConnectionRepo, TenantDomainRepo, TenantRepo, bootstrap_system_tenant, create_pool,
    },
    middleware::auth_middleware,
    proto::iam::v1::{FederationServiceExt, IdentityServiceExt, TenantServiceExt},
    services::handlers::saml::{SamlState, router as saml_router},
    services::{
        federation::FederationServiceImpl, identity::IdentityServiceImpl, tenant::TenantServiceImpl,
    },
    session_token::SessionTokenSigner,
};
use sso_ory_client::KratosClient;
use sunbeam_g2v::{
    health::HealthRouter,
    router::ServiceRouter,
    server::{axum::bind_random_port, builder::ServerBuilder},
};

mod support;

fn build_saml_response(
    request_id: &str,
    sp_entity_id: &str,
    acs_url: &str,
    email: &str,
    signer: Option<&gamlastan::crypto::SamlSigner>,
) -> String {
    use chrono::Utc;
    use gamlastan::core::assertion::attribute::{Attribute, AttributeValue};
    use gamlastan::core::assertion::name_id::NameId;
    use gamlastan::core::constants;
    use gamlastan::profiles::sso::idp::create_response;
    use gamlastan::profiles::sso::web_browser::{ResponseOptions, ResponseTimes};
    use gamlastan::xml::SamlSerialize;

    let options = ResponseOptions {
        idp_entity_id: "https://idp.example.com".to_string(),
        in_response_to: Some(request_id.to_string()),
        sp_entity_id: sp_entity_id.to_string(),
        acs_url: acs_url.to_string(),
        assertion_lifetime_seconds: 300,
        session_index: Some("_session_1".to_string()),
        session_not_on_or_after: None,
        authn_context_class_ref: Some(constants::AUTHN_CONTEXT_PASSWORD.to_string()),
        client_address: None,
        attributes: vec![Attribute {
            name: "email".to_string(),
            name_format: None,
            friendly_name: None,
            values: vec![AttributeValue::String(email.to_string())],
        }],
    };
    let name_id = NameId {
        value: email.to_string(),
        format: Some(constants::NAMEID_EMAIL.to_string()),
        name_qualifier: None,
        sp_name_qualifier: None,
        sp_provided_id: None,
    };
    let response = create_response(&options, &name_id, ResponseTimes::at(Utc::now()));
    let response_id = response.base.id.clone();
    let mut xml = response.to_xml_string().expect("serialize response");

    if let Some(signer) = signer {
        let template = response_signature_template(&response_id);
        let status_pos = xml
            .find("<samlp:Status")
            .expect("status element in serialized response");
        xml.insert_str(status_pos, &template);
        xml = signer.sign_enveloped(&xml).expect("sign saml response");
    }

    xml
}

fn response_signature_template(response_id: &str) -> String {
    format!(
        r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference URI="#{response_id}">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue></ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue></ds:SignatureValue>
            <ds:KeyInfo><ds:X509Data/></ds:KeyInfo>
        </ds:Signature>"##
    )
}

#[tokio::test]
async fn federation_saml_login_round_trip() {
    let (_pg, database_url) = support::start_postgres()
        .await
        .expect("postgres should start");
    let (_kratos, kratos_admin_url, _kratos_public_url) =
        support::start_kratos().await.expect("kratos should start");

    let pool = create_pool(&database_url, false)
        .await
        .expect("database pool should be created");

    let system_tenant_ulid = ulid::Ulid::new().to_string();
    bootstrap_system_tenant(&pool, &system_tenant_ulid)
        .await
        .expect("system tenant should bootstrap");
    support::bootstrap_test_subject_mapping(&pool, &system_tenant_ulid).await;

    let schemas = IdentitySchemaRepo::new(pool.clone());
    schemas
        .create(
            &system_tenant_ulid,
            "default",
            json!({
                "$id": "https://schemas.ory.sh/presets/kratos/quickstart/email-password/identity.schema.json",
                "$schema": "http://json-schema.org/draft-07/schema#",
                "title": "Person",
                "type": "object",
                "properties": {
                    "traits": {
                        "type": "object",
                        "properties": {
                            "email": {
                                "type": "string",
                                "format": "email",
                                "title": "E-Mail",
                                "ory.sh/kratos": {
                                    "credentials": { "password": { "identifier": true } },
                                    "recovery": { "via": "email" },
                                    "verification": { "via": "email" }
                                }
                            },
                            "tenant_id": { "type": "string" }
                        },
                        "required": ["email"],
                        "additionalProperties": false
                    }
                }
            }),
            true,
        )
        .await
        .expect("schema should be registered");

    let providers = SamlProviderRepo::new(pool.clone());
    let provider = providers
        .create(
            &system_tenant_ulid,
            "test-idp",
            "https://idp.example.com",
            "https://idp.example.com/sso",
            None,
            "https://sp.example.com",
            "https://sp.example.com/acs",
            Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
            "default",
            false,
        )
        .await
        .expect("provider should be created");

    let kratos = Arc::new(
        KratosClient::new_with_public(&kratos_admin_url, &_kratos_public_url)
            .expect("kratos client should build"),
    );
    let mappings = IdMappingRepo::new(pool.clone());
    let requests = SamlRequestRepo::new(pool.clone());
    let federation_mappings = SamlIdentityMappingRepo::new(pool.clone());
    let idp_keys = SamlIdpKeyRepo::new(pool.clone());
    let connections = TenantConnectionRepo::new(pool.clone());
    let domains = TenantDomainRepo::new(pool.clone());
    let login_state = LoginStateRepo::new(pool.clone());
    let tenant_repo = TenantRepo::new(pool);
    let replay_cache: Arc<dyn SamlReplayCacheTrait> = Arc::new(InMemoryReplayCache::new());

    let tenant_service = Arc::new(TenantServiceImpl::new(
        tenant_repo,
        system_tenant_ulid.clone(),
    ));
    let identity_service = Arc::new(IdentityServiceImpl::new(
        kratos.clone(),
        mappings.clone(),
        schemas.clone(),
        "http://gateway.test".to_string(),
    ));
    let federation_service = Arc::new(FederationServiceImpl::new(
        kratos.clone(),
        providers,
        requests,
        mappings.clone(),
        federation_mappings,
        schemas,
        idp_keys,
        connections,
        domains,
        login_state,
        // hydra_public_url is not used by the SAML flow; point it at kratos public to keep the
        // service constructible in this test.
        _kratos_public_url.clone(),
        _kratos_public_url.clone(),
        None,
        None,
        std::time::Duration::from_secs(900),
        false,
        false,
        replay_cache,
    ));

    let connect_router: ConnectRouter = tenant_service.register(ConnectRouter::new());
    let connect_router: ConnectRouter = identity_service.register(connect_router);
    let connect_router: ConnectRouter = federation_service.register(connect_router);
    let service_router = ServiceRouter::from_router(connect_router);

    let server = ServerBuilder::new()
        .with_router(service_router)
        .with_health(HealthRouter::new())
        .build_axum()
        .expect("server should build");

    let app = server
        .app()
        .layer(from_fn(auth_middleware))
        .layer(Extension(SessionTokenSigner::new(
            "test-secret-that-is-at-least-32-bytes-long",
            3600,
            "https://gateway.example.com",
        )))
        .layer(Extension(support::test_introspector()))
        .layer(Extension(support::test_session_store()))
        .layer(Extension(kratos))
        .layer(Extension(Arc::new(mappings) as Arc<dyn IdMappingStore>));

    let (listener, addr) = bind_random_port("127.0.0.1")
        .await
        .expect("random port should bind");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("server should run");
    });

    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    // Initiate SAML login.
    let initiate_resp = client
        .post(format!("{base}/iam.v1.FederationService/InitiateSamlLogin"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({
            "providerId": provider.id,
            "relayState": "after-login"
        }))
        .send()
        .await
        .expect("initiate saml login request should succeed");

    assert!(
        initiate_resp.status().is_success(),
        "initiate saml login failed: {}",
        initiate_resp.text().await.unwrap_or_default()
    );

    let login: serde_json::Value = initiate_resp
        .json()
        .await
        .expect("login response should be json");
    let request_id = login["requestId"]
        .as_str()
        .expect("request id should exist");
    let redirect_url = login["redirectUrl"]
        .as_str()
        .expect("redirect url should exist");
    assert!(redirect_url.contains("https://idp.example.com/sso"));
    assert!(redirect_url.contains("SAMLRequest="));

    // Build a SAML response as if it came back from the IdP.
    let saml_xml = build_saml_response(
        request_id,
        &provider.sp_entity_id,
        &provider.acs_url,
        "alice@example.com",
        None,
    );
    let encoded_assertion = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        saml_xml.as_bytes(),
    );

    let accept_resp = client
        .post(format!(
            "{base}/iam.v1.FederationService/AcceptSamlAssertion"
        ))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({
            "providerId": provider.id,
            "encodedAssertion": encoded_assertion,
            "relayState": "after-login"
        }))
        .send()
        .await
        .expect("accept saml assertion request should succeed");

    assert!(
        accept_resp.status().is_success(),
        "accept saml assertion failed: {}",
        accept_resp.text().await.unwrap_or_default()
    );

    let session: serde_json::Value = accept_resp.json().await.expect("session should be json");
    assert!(session["id"].as_str().is_some());
    assert!(session["identityId"].as_str().is_some());
    assert_eq!(session["tenantId"], system_tenant_ulid);
    assert_eq!(session["active"], true);

    // Verify the JIT-provisioned identity is reachable through the identity service.
    let identity_id = session["identityId"].as_str().unwrap();
    let get_resp = client
        .post(format!("{base}/iam.v1.IdentityService/GetIdentity"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({ "id": identity_id }))
        .send()
        .await
        .expect("get identity request should succeed");

    assert!(get_resp.status().is_success(), "get identity failed");
    let identity: serde_json::Value = get_resp.json().await.expect("identity should be json");
    assert_eq!(identity["id"], identity_id);
    assert_eq!(identity["schemaId"], "default");
    assert_eq!(identity["traits"]["email"], "alice@example.com");

    let _ = shutdown_tx.send(());
    handle.await.expect("server task should finish");
}

#[tokio::test]
async fn federation_saml_signed_login_is_idempotent() {
    let (_pg, database_url) = support::start_postgres()
        .await
        .expect("postgres should start");
    let (_kratos, kratos_admin_url, _kratos_public_url) =
        support::start_kratos().await.expect("kratos should start");

    let pool = create_pool(&database_url, false)
        .await
        .expect("database pool should be created");

    let system_tenant_ulid = ulid::Ulid::new().to_string();
    bootstrap_system_tenant(&pool, &system_tenant_ulid)
        .await
        .expect("system tenant should bootstrap");
    support::bootstrap_test_subject_mapping(&pool, &system_tenant_ulid).await;

    let schemas = IdentitySchemaRepo::new(pool.clone());
    schemas
        .create(
            &system_tenant_ulid,
            "default",
            json!({
                "$id": "https://schemas.ory.sh/presets/kratos/quickstart/email-password/identity.schema.json",
                "$schema": "http://json-schema.org/draft-07/schema#",
                "title": "Person",
                "type": "object",
                "properties": {
                    "traits": {
                        "type": "object",
                        "properties": {
                            "email": {
                                "type": "string",
                                "format": "email",
                                "title": "E-Mail",
                                "ory.sh/kratos": {
                                    "credentials": { "password": { "identifier": true } },
                                    "recovery": { "via": "email" },
                                    "verification": { "via": "email" }
                                }
                            },
                            "tenant_id": { "type": "string" }
                        },
                        "required": ["email"],
                        "additionalProperties": false
                    }
                }
            }),
            true,
        )
        .await
        .expect("schema should be registered");

    let key_pem = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/saml-test-key.pem"
    ))
    .expect("read saml test key");
    let cert_pem = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/saml-test-cert.pem"
    ))
    .expect("read saml test cert");

    let key_manager =
        gamlastan::crypto::keys::build_idp_keys_manager(&key_pem).expect("load saml test key");
    let signer = Arc::new(gamlastan::crypto::SamlSigner::new(key_manager));

    let providers = SamlProviderRepo::new(pool.clone());
    let provider = providers
        .create(
            &system_tenant_ulid,
            "test-idp",
            "https://idp.example.com",
            "https://idp.example.com/sso",
            Some(&cert_pem),
            "https://sp.example.com",
            "https://sp.example.com/acs",
            Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
            "default",
            false,
        )
        .await
        .expect("provider should be created");

    let kratos = Arc::new(
        KratosClient::new_with_public(&kratos_admin_url, &_kratos_public_url)
            .expect("kratos client should build"),
    );
    let mappings = IdMappingRepo::new(pool.clone());
    let requests = SamlRequestRepo::new(pool.clone());
    let federation_mappings = SamlIdentityMappingRepo::new(pool.clone());
    let idp_keys = SamlIdpKeyRepo::new(pool.clone());
    let connections = TenantConnectionRepo::new(pool.clone());
    let domains = TenantDomainRepo::new(pool.clone());
    let login_state = LoginStateRepo::new(pool.clone());
    let tenant_repo = TenantRepo::new(pool);
    let replay_cache: Arc<dyn SamlReplayCacheTrait> = Arc::new(InMemoryReplayCache::new());

    let tenant_service = Arc::new(TenantServiceImpl::new(
        tenant_repo,
        system_tenant_ulid.clone(),
    ));
    let identity_service = Arc::new(IdentityServiceImpl::new(
        kratos.clone(),
        mappings.clone(),
        schemas.clone(),
        "http://gateway.test".to_string(),
    ));
    let federation_service = Arc::new(FederationServiceImpl::new(
        kratos.clone(),
        providers,
        requests,
        mappings.clone(),
        federation_mappings,
        schemas,
        idp_keys,
        connections,
        domains,
        login_state,
        _kratos_public_url.clone(),
        _kratos_public_url.clone(),
        Some(signer.clone()),
        Some(cert_pem),
        std::time::Duration::from_secs(900),
        true,
        false,
        replay_cache,
    ));

    let connect_router: ConnectRouter = tenant_service.register(ConnectRouter::new());
    let connect_router: ConnectRouter = identity_service.register(connect_router);
    let connect_router: ConnectRouter = federation_service.register(connect_router);
    let service_router = ServiceRouter::from_router(connect_router);

    let server = ServerBuilder::new()
        .with_router(service_router)
        .with_health(HealthRouter::new())
        .build_axum()
        .expect("server should build");

    let app = server
        .app()
        .layer(from_fn(auth_middleware))
        .layer(Extension(SessionTokenSigner::new(
            "test-secret-that-is-at-least-32-bytes-long",
            3600,
            "https://gateway.example.com",
        )))
        .layer(Extension(support::test_introspector()))
        .layer(Extension(support::test_session_store()))
        .layer(Extension(kratos))
        .layer(Extension(Arc::new(mappings) as Arc<dyn IdMappingStore>));

    let (listener, addr) = bind_random_port("127.0.0.1")
        .await
        .expect("random port should bind");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("server should run");
    });

    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    let initiate_resp = client
        .post(format!("{base}/iam.v1.FederationService/InitiateSamlLogin"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({
            "providerId": provider.id,
            "relayState": "after-login"
        }))
        .send()
        .await
        .expect("initiate saml login request should succeed");

    assert!(
        initiate_resp.status().is_success(),
        "initiate saml login failed: {}",
        initiate_resp.text().await.unwrap_or_default()
    );

    let login: serde_json::Value = initiate_resp
        .json()
        .await
        .expect("login response should be json");
    let request_id = login["requestId"]
        .as_str()
        .expect("request id should exist");
    let redirect_url = login["redirectUrl"]
        .as_str()
        .expect("redirect url should exist");
    assert!(redirect_url.contains("https://idp.example.com/sso"));
    assert!(redirect_url.contains("SAMLRequest="));
    assert!(redirect_url.contains("Signature="));
    assert!(redirect_url.contains("SigAlg="));

    let saml_xml = build_saml_response(
        request_id,
        &provider.sp_entity_id,
        &provider.acs_url,
        "alice@example.com",
        Some(&signer),
    );
    let encoded_assertion = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        saml_xml.as_bytes(),
    );

    let accept_resp = client
        .post(format!(
            "{base}/iam.v1.FederationService/AcceptSamlAssertion"
        ))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({
            "providerId": provider.id,
            "encodedAssertion": encoded_assertion,
            "relayState": "after-login"
        }))
        .send()
        .await
        .expect("accept saml assertion request should succeed");

    assert!(
        accept_resp.status().is_success(),
        "accept saml assertion failed: {}",
        accept_resp.text().await.unwrap_or_default()
    );

    let session: serde_json::Value = accept_resp.json().await.expect("session should be json");
    let first_identity_id = session["identityId"]
        .as_str()
        .expect("identity id")
        .to_string();
    assert_eq!(session["tenantId"], system_tenant_ulid);
    assert_eq!(session["active"], true);

    // A subsequent login for the same federated user must return the same
    // identity (idempotent JIT provisioning) without creating a duplicate.
    let initiate_resp2 = client
        .post(format!("{base}/iam.v1.FederationService/InitiateSamlLogin"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({"providerId": provider.id, "relayState": "after-login"}))
        .send()
        .await
        .expect("second initiate request should succeed");
    assert!(initiate_resp2.status().is_success());
    let login2: serde_json::Value = initiate_resp2
        .json()
        .await
        .expect("login response should be json");
    let request_id2 = login2["requestId"]
        .as_str()
        .expect("request id should exist");

    let saml_xml2 = build_saml_response(
        request_id2,
        &provider.sp_entity_id,
        &provider.acs_url,
        "alice@example.com",
        Some(&signer),
    );
    let encoded_assertion2 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        saml_xml2.as_bytes(),
    );
    let accept_resp2 = client
        .post(format!(
            "{base}/iam.v1.FederationService/AcceptSamlAssertion"
        ))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({
            "providerId": provider.id,
            "encodedAssertion": encoded_assertion2,
            "relayState": "after-login"
        }))
        .send()
        .await
        .expect("second accept request should succeed");

    assert!(
        accept_resp2.status().is_success(),
        "second accept saml assertion failed: {}",
        accept_resp2.text().await.unwrap_or_default()
    );

    let session2: serde_json::Value = accept_resp2.json().await.expect("session should be json");
    assert_eq!(
        session2["identityId"].as_str().expect("identity id"),
        first_identity_id
    );

    let _ = shutdown_tx.send(());
    handle.await.expect("server task should finish");
}

#[tokio::test]
async fn federation_saml_metadata_endpoint() {
    let (_pg, database_url) = support::start_postgres()
        .await
        .expect("postgres should start");

    let pool = create_pool(&database_url, false)
        .await
        .expect("database pool should be created");

    let system_tenant_ulid = ulid::Ulid::new().to_string();
    bootstrap_system_tenant(&pool, &system_tenant_ulid)
        .await
        .expect("system tenant should bootstrap");

    let key_pem = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/saml-test-key.pem"
    ))
    .expect("read saml test key");
    let cert_pem = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/saml-test-cert.pem"
    ))
    .expect("read saml test cert");

    let key_manager =
        gamlastan::crypto::keys::build_idp_keys_manager(&key_pem).expect("load saml test key");
    let signer = Arc::new(gamlastan::crypto::SamlSigner::new(key_manager));

    let providers = SamlProviderRepo::new(pool.clone());
    let provider = providers
        .create(
            &system_tenant_ulid,
            "test-idp",
            "https://idp.example.com",
            "https://idp.example.com/sso",
            Some(&cert_pem),
            "https://sp.example.com",
            "/saml/acs",
            Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
            "default",
            true,
        )
        .await
        .expect("provider should be created");

    let kratos = Arc::new(
        KratosClient::new_with_public("http://127.0.0.1:4434", "http://127.0.0.1:4433")
            .expect("kratos client should build"),
    );
    let mappings = IdMappingRepo::new(pool.clone());
    let requests = SamlRequestRepo::new(pool.clone());
    let federation_mappings = SamlIdentityMappingRepo::new(pool.clone());
    let idp_keys = SamlIdpKeyRepo::new(pool.clone());
    let schemas = IdentitySchemaRepo::new(pool.clone());
    let connections = TenantConnectionRepo::new(pool.clone());
    let domains = TenantDomainRepo::new(pool.clone());
    let login_state = LoginStateRepo::new(pool.clone());
    let replay_cache = Arc::new(SamlReplayCache::new(pool));

    let federation_service = Arc::new(FederationServiceImpl::new(
        kratos,
        providers,
        requests,
        mappings,
        federation_mappings,
        schemas,
        idp_keys,
        connections,
        domains,
        login_state,
        "http://127.0.0.1:4444".to_string(),
        "http://gateway.example.com".to_string(),
        Some(signer),
        Some(cert_pem),
        std::time::Duration::from_secs(900),
        true,
        false,
        replay_cache,
    ));

    let saml_state = Arc::new(SamlState::new(federation_service));

    let app = axum::Router::new().merge(saml_router(saml_state));

    let (listener, addr) = bind_random_port("127.0.0.1")
        .await
        .expect("random port should bind");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("server should run");
    });

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "http://{addr}/saml/metadata?provider_id={}",
            provider.id
        ))
        .send()
        .await
        .expect("metadata request should succeed");

    assert!(
        resp.status().is_success(),
        "metadata endpoint failed: {}",
        resp.text().await.unwrap_or_default()
    );

    let body = resp.text().await.expect("metadata body should be text");
    assert!(body.contains(r#"entityID="https://sp.example.com""#));
    assert!(body.contains(
        r#"AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://gateway.example.com/saml/acs""#
    ));
    assert!(body.contains(r#"AuthnRequestsSigned="true""#));
    assert!(body.contains(r#"WantAssertionsSigned="true""#));
    assert!(body.contains("<md:KeyDescriptor use=\"signing\">"));
    assert!(body.contains("<ds:X509Certificate>"));

    let _ = shutdown_tx.send(());
    handle.await.expect("server task should finish");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn federation_saml_db_replay_cache_rejects_duplicates() {
    let (_pg, database_url) = support::start_postgres()
        .await
        .expect("postgres should start");

    let pool = create_pool(&database_url, false)
        .await
        .expect("database pool should be created");

    let cache = SamlReplayCache::new(pool);
    let expiry = chrono::Utc::now() + chrono::Duration::seconds(300);

    assert!(
        cache
            .check_and_insert("_assertion_1", expiry)
            .await
            .unwrap()
    );
    assert!(
        !cache
            .check_and_insert("_assertion_1", expiry)
            .await
            .unwrap()
    );
    assert!(
        cache
            .check_and_insert("_assertion_2", expiry)
            .await
            .unwrap()
    );
}
