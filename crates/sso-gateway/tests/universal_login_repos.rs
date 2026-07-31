// SSO-027: tests may unwrap/expect freely; the panic/default bans target production code.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods))]

use serde_json::json;
use sso_gateway::db::{
    ConnectionType, LocalAuthMethod, TenantConnectionRepo, TenantDomainRepo, TenantLocalAuthRepo,
    TenantRepo, bootstrap_system_tenant, create_pool,
};

mod support;

#[tokio::test]
async fn tenant_connection_repo_round_trip() {
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

    let tenants = TenantRepo::new(pool.clone());
    let tenant = tenants
        .create("acme", "Acme Corp", json!({}))
        .await
        .expect("tenant should be created");

    let domains = TenantDomainRepo::new(pool.clone());
    let domain = domains
        .create(&tenant.id, "auth.acme.com")
        .await
        .expect("domain should be created");
    domains
        .mark_verified(&tenant.id, &domain.id)
        .await
        .expect("domain should be verified");

    let connections = TenantConnectionRepo::new(pool.clone());
    let created = connections
        .create(
            &tenant.id,
            ConnectionType::Oidc,
            "auth.acme.com",
            json!({"issuer": "https://auth.acme.com"}),
        )
        .await
        .expect("connection should be created");

    assert_eq!(created.tenant_id, tenant.id);
    assert_eq!(created.connection_type, ConnectionType::Oidc);
    assert_eq!(created.domain, "auth.acme.com");
    assert!(created.is_enabled);

    let by_domain = connections
        .get_by_domain("auth.acme.com")
        .await
        .expect("connection should be found by domain");
    assert_eq!(by_domain.id, created.id);

    let by_id = connections
        .get_by_id(&tenant.id, &created.id)
        .await
        .expect("connection should be found by id");
    assert_eq!(by_id.id, created.id);

    let listed = connections
        .list_by_tenant(&tenant.id)
        .await
        .expect("connections should be listed");
    assert_eq!(listed.len(), 1);

    let updated = connections
        .update_config(
            &tenant.id,
            &created.id,
            json!({"issuer": "https://idp.acme.com"}),
        )
        .await
        .expect("config should be updated");
    assert_eq!(updated.config["issuer"], "https://idp.acme.com");

    let disabled = connections
        .set_enabled(&tenant.id, &created.id, false)
        .await
        .expect("connection should be disabled");
    assert!(!disabled.is_enabled);

    assert!(
        connections.get_by_domain("auth.acme.com").await.is_err(),
        "disabled connection should not be returned by domain lookup"
    );

    let reenabled = connections
        .set_enabled(&tenant.id, &created.id, true)
        .await
        .expect("connection should be re-enabled");
    assert!(reenabled.is_enabled);
    assert!(
        connections.get_by_domain("auth.acme.com").await.is_ok(),
        "re-enabled connection should be returned by domain lookup"
    );
}

#[tokio::test]
async fn tenant_connection_repo_errors_for_missing_rows() {
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

    let tenants = TenantRepo::new(pool.clone());
    let tenant = tenants
        .create("acme", "Acme Corp", json!({}))
        .await
        .expect("tenant should be created");

    let connections = TenantConnectionRepo::new(pool.clone());
    assert!(
        connections
            .get_by_domain("missing.example.com")
            .await
            .is_err()
    );
    assert!(
        connections
            .get_by_id(&tenant.id, "01ABCDEF0123456789ABCDEF")
            .await
            .is_err()
    );
    assert!(
        connections
            .list_by_tenant(&tenant.id)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn tenant_local_auth_repo_round_trip() {
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

    let tenants = TenantRepo::new(pool.clone());
    let tenant = tenants
        .create("acme", "Acme Corp", json!({}))
        .await
        .expect("tenant should be created");

    let local_auth = TenantLocalAuthRepo::new(pool.clone());
    let created = local_auth
        .create(&tenant.id, LocalAuthMethod::Password, json!({}))
        .await
        .expect("local auth should be created");

    assert_eq!(created.tenant_id, tenant.id);
    assert_eq!(created.method, LocalAuthMethod::Password);
    assert!(created.is_enabled);

    let by_method = local_auth
        .get_by_tenant_and_method(&tenant.id, LocalAuthMethod::Password)
        .await
        .expect("local auth should be found");
    assert_eq!(by_method.id, created.id);

    let listed = local_auth
        .list_by_tenant(&tenant.id)
        .await
        .expect("local auth methods should be listed");
    assert_eq!(listed.len(), 1);

    let updated = local_auth
        .update_config(&tenant.id, &created.id, json!({"mfa": true}))
        .await
        .expect("config should be updated");
    assert_eq!(updated.config["mfa"], true);

    let disabled = local_auth
        .set_enabled(&tenant.id, &created.id, false)
        .await
        .expect("local auth should be disabled");
    assert!(!disabled.is_enabled);

    assert!(
        local_auth
            .get_by_tenant_and_method(&tenant.id, LocalAuthMethod::Password)
            .await
            .is_err(),
        "disabled local auth should not be returned"
    );

    let code = local_auth
        .create(&tenant.id, LocalAuthMethod::Code, json!({}))
        .await
        .expect("code local auth should be created");
    assert_eq!(code.method, LocalAuthMethod::Code);
}

#[tokio::test]
async fn tenant_domain_repo_round_trip() {
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

    let tenants = TenantRepo::new(pool.clone());
    let tenant = tenants
        .create("acme", "Acme Corp", json!({}))
        .await
        .expect("tenant should be created");

    let domains = TenantDomainRepo::new(pool.clone());
    let created = domains
        .create(&tenant.id, "acme.com")
        .await
        .expect("domain should be created");

    assert_eq!(created.tenant_id, tenant.id);
    assert_eq!(created.domain, "acme.com");
    assert!(!created.is_verified);
    assert!(created.verified_at.is_none());
    assert_eq!(created.verification_token.len(), 64);

    let by_domain = domains
        .get_by_domain("acme.com")
        .await
        .expect("domain should be found by domain");
    assert_eq!(by_domain.id, created.id);
    assert_eq!(by_domain.verification_token, created.verification_token);

    let listed = domains
        .list_by_tenant(&tenant.id)
        .await
        .expect("domains should be listed");
    assert_eq!(listed.len(), 1);

    let verified = domains
        .mark_verified(&tenant.id, &created.id)
        .await
        .expect("domain should be verified");
    assert!(verified.is_verified);
    assert!(verified.verified_at.is_some());
}

#[tokio::test]
async fn tenant_domain_repo_unique_domain() {
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

    let tenants = TenantRepo::new(pool.clone());
    let tenant_a = tenants
        .create("acme", "Acme Corp", json!({}))
        .await
        .expect("tenant a should be created");
    let tenant_b = tenants
        .create("contoso", "Contoso", json!({}))
        .await
        .expect("tenant b should be created");

    let domains = TenantDomainRepo::new(pool.clone());
    domains
        .create(&tenant_a.id, "shared.example.com")
        .await
        .expect("domain should be created for tenant a");

    let err = domains
        .create(&tenant_b.id, "shared.example.com")
        .await
        .expect_err("duplicate domain should fail");
    assert!(
        matches!(
            err,
            sso_gateway::db::DbError::Sqlx(sqlx::Error::Database(_))
        ),
        "expected unique violation, got {err:?}"
    );
}
