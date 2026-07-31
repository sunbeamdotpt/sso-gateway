// SSO-027: tests may unwrap/expect freely; the panic/default bans target production code.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods))]

use sso_gateway::db::{
    DbError, IdMappingRepo, IdentitySchemaRepo, PermissionTupleRepo, ScimGroupRepo, TenantRepo,
    bootstrap_system_tenant, create_pool,
};

mod support;

#[tokio::test]
async fn db_edge_cases() {
    let (_pg, database_url) = support::start_postgres()
        .await
        .expect("postgres should start");

    let pool = create_pool(&database_url, false)
        .await
        .expect("database pool should be created");

    let tenant_id = ulid::Ulid::new().to_string();

    // First bootstrap call creates the system tenant.
    let first = bootstrap_system_tenant(&pool, &tenant_id)
        .await
        .expect("system tenant should bootstrap");
    assert_eq!(first, tenant_id);

    // A second call with the same id is idempotent.
    let second = bootstrap_system_tenant(&pool, &tenant_id)
        .await
        .expect("re-bootstrap should succeed");
    assert_eq!(second, tenant_id);

    let tenants = TenantRepo::new(pool.clone());
    assert!(matches!(
        tenants.get_by_id("not-a-tenant").await.unwrap_err(),
        DbError::TenantNotFound
    ));

    let mappings = IdMappingRepo::new(pool.clone());
    assert!(matches!(
        mappings
            .get_public_id(&tenant_id, "hydra", "ory-123")
            .await
            .unwrap_err(),
        DbError::MappingNotFound
    ));
    assert!(matches!(
        mappings
            .delete(&tenant_id, "hydra", "pub-123")
            .await
            .unwrap_err(),
        DbError::MappingNotFound
    ));

    let schemas = IdentitySchemaRepo::new(pool.clone());
    assert!(matches!(
        schemas.delete(&tenant_id, "missing").await.unwrap_err(),
        DbError::SchemaNotFound
    ));

    let tuples = PermissionTupleRepo::new(pool.clone());
    assert!(matches!(
        tuples.delete(&tenant_id, "missing").await.unwrap_err(),
        DbError::TupleNotFound
    ));
    tuples
        .create(&tenant_id, "app", "obj1", "owner", "sub1")
        .await
        .expect("tuple should be created");
    assert_eq!(
        tuples
            .list(&tenant_id, None, None, None)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        tuples
            .list(&tenant_id, Some("app"), None, None)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        tuples
            .list(&tenant_id, Some("app"), Some("obj1"), None)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        tuples
            .list(&tenant_id, Some("app"), Some("obj1"), Some("owner"))
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        tuples
            .list(&tenant_id, Some("other"), None, None)
            .await
            .unwrap()
            .is_empty()
    );

    let groups = ScimGroupRepo::new(pool.clone());
    assert!(matches!(
        groups.get(&tenant_id, "missing").await.unwrap_err(),
        DbError::TenantNotFound
    ));
    assert!(matches!(
        groups.delete(&tenant_id, "missing").await.unwrap_err(),
        DbError::TenantNotFound
    ));
}
