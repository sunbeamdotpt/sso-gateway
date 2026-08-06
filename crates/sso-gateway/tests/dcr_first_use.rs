// SSO-027: tests may unwrap/expect freely; the panic/default bans target production code.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)
)]

//! Consent-gated first-use entitlement integration tests (SSO-039 §2-4),
//! against real Postgres + Hydra + Kratos + permissions-backend containers,
//! on both the `keto` and `openfga` features.
//!
//! The login gate (`IdentitySelfService::CreateLoginFlow` with a live Kratos
//! session) and the consent gate (`OAuth2ConsentService::AcceptConsent`) are
//! exercised at the service level with real backends, driving real Hydra
//! login/consent challenges end to end.

use std::sync::Arc;

use buffa::{HasMessageView, Message, MessageView, bytes::Bytes};
use connectrpc::{ErrorCode, RequestContext, ServiceRequest};
use serde_json::{Value, json};
use sso_gateway::auth::{AuthContext, SubjectType};
use sso_gateway::db::{
    ApplicationRepo, IdMappingRepo, IdMappingStore, IdentitySchemaRepo, REGISTRATION_SOURCE_ADMIN,
    REGISTRATION_SOURCE_DCR, TenantMembershipRepo, TransientTokenRepo, create_pool,
};
use sso_gateway::middleware::TenantId;
use sso_gateway::proto::iam::v1::{
    AcceptConsentRequest, CreateLoginFlowRequest, GetChallengeRequest, IdentitySelfService,
    OAuth2ConsentService,
};
use sso_gateway::services::entitlement::{
    EntitlementLevel, EntitlementService, EntitlementServiceImpl,
};
use sso_gateway::services::identity_self_service::IdentitySelfServiceImpl;
use sso_gateway::services::oauth2_consent::OAuth2ConsentServiceImpl;
use sso_gateway::services::permission::PermissionBackend;
use sso_ory_client::{HydraClient, KratosClient};
use testcontainers::{ContainerAsync, GenericImage};

mod support;

const REDIRECT_URI: &str = "https://app.example.com/callback";
const ENTITLEMENT_NAMESPACE: &str = "entitlements";

/// Hydra runs on an in-memory store that answers concurrent writes with
/// "Unable to serialize access due to a concurrent update in another
/// session" errors, so the browser flows must not run at the same time
/// (same shared-backend hazard as KETO_WRITE_LOCK/BOOT_LOCK).
static FLOW_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Postgres, Hydra, and Kratos containers shared by every test in this
/// binary; per-feature Keto/OpenFGA containers live in the feature modules.
struct Shared {
    database_url: String,
    hydra_admin_url: String,
    hydra_public_url: String,
    kratos_admin_url: String,
    kratos_public_url: String,
    #[allow(dead_code)]
    pg: ContainerAsync<GenericImage>,
    #[allow(dead_code)]
    hydra: ContainerAsync<GenericImage>,
    #[allow(dead_code)]
    kratos: ContainerAsync<GenericImage>,
}

static SHARED: tokio::sync::OnceCell<Shared> = tokio::sync::OnceCell::const_new();

async fn shared() -> &'static Shared {
    SHARED
        .get_or_init(|| async {
            let (pg, database_url) = support::start_postgres()
                .await
                .expect("postgres should start");
            let (hydra, hydra_admin_url, hydra_public_url) =
                support::start_hydra().await.expect("hydra should start");
            let (kratos, kratos_admin_url, kratos_public_url) =
                support::start_kratos().await.expect("kratos should start");
            Shared {
                database_url,
                hydra_admin_url,
                hydra_public_url,
                kratos_admin_url,
                kratos_public_url,
                pg,
                hydra,
                kratos,
            }
        })
        .await
}

/// The gateway services under test plus direct handles to the backing stores.
struct Services {
    self_service: IdentitySelfServiceImpl,
    consent: OAuth2ConsentServiceImpl,
    entitlements: Arc<dyn EntitlementService>,
    backend: Arc<dyn PermissionBackend>,
    hydra: Arc<HydraClient>,
    kratos: Arc<KratosClient>,
    mappings: IdMappingRepo,
    applications: ApplicationRepo,
    pool: sqlx::PgPool,
    hydra_public_url: String,
    kratos_public_url: String,
}

async fn build_services(backend: Arc<dyn PermissionBackend>) -> Services {
    let shared = shared().await;
    let pool = create_pool(&shared.database_url, false)
        .await
        .expect("database pool should be created");
    let hydra = Arc::new(
        HydraClient::new(&shared.hydra_admin_url, &shared.hydra_public_url)
            .expect("hydra client should build"),
    );
    let kratos = Arc::new(
        KratosClient::new_with_public(&shared.kratos_admin_url, &shared.kratos_public_url)
            .expect("kratos client should build"),
    );
    let mappings = IdMappingRepo::new(pool.clone());
    let applications = ApplicationRepo::new(pool.clone());
    let entitlements: Arc<dyn EntitlementService> = Arc::new(EntitlementServiceImpl::new(
        backend.clone(),
        Arc::new(applications.clone()),
    ));
    let self_service = IdentitySelfServiceImpl::new(
        kratos.clone(),
        hydra.clone(),
        TransientTokenRepo::new(pool.clone()),
        mappings.clone(),
        Arc::new(applications.clone()),
        IdentitySchemaRepo::new(pool.clone()),
        TenantMembershipRepo::new(pool.clone()),
        entitlements.clone(),
        true,
        shared.kratos_public_url.clone(),
        shared.hydra_public_url.clone(),
        // Point the "gateway" public URL at Hydra itself so accepted-login
        // redirects pass through unrewritten.
        shared.hydra_public_url.clone(),
        "default".to_string(),
        sso_gateway::config::SelfServicePaths::default(),
    );
    let consent = OAuth2ConsentServiceImpl::new(
        hydra.clone(),
        kratos.clone(),
        TransientTokenRepo::new(pool.clone()),
        mappings.clone(),
        Arc::new(applications.clone()),
        entitlements.clone(),
        Vec::new(),
    );
    Services {
        self_service,
        consent,
        entitlements,
        backend,
        hydra,
        kratos,
        mappings,
        applications,
        pool,
        hydra_public_url: shared.hydra_public_url.clone(),
        kratos_public_url: shared.kratos_public_url.clone(),
    }
}

/// Rewrite Hydra's configured issuer origin onto the mapped public URL so
/// `redirect_to` values are reachable from the test host.
fn rewrite_hydra_origin(url: &str, hydra_public_url: &str) -> String {
    let target = url::Url::parse(hydra_public_url).expect("hydra public url");
    let mut parsed = url::Url::parse(url).expect("redirect should be a url");
    parsed
        .set_scheme(target.scheme())
        .expect("scheme should set");
    parsed.set_host(target.host_str()).expect("host should set");
    parsed.set_port(target.port()).expect("port should set");
    parsed.to_string()
}

fn extract_query_param(url: &str, key: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()?
        .query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

fn no_redirect_client() -> reqwest::Client {
    reqwest::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("no-redirect client should build")
}

fn service_request<Req>(msg: Req) -> ServiceRequest<'static, Req>
where
    Req: Message + HasMessageView,
{
    let bytes = Bytes::from(msg.encode_to_vec());
    let bytes: &'static Bytes = Box::leak(Box::new(bytes));
    let view = Req::View::decode_view(bytes).unwrap();
    let view: &'static Req::View<'static> = Box::leak(Box::new(view));
    ServiceRequest::from_parts(view, bytes)
}

fn login_context(tenant_id: &str, session_cookie: &str) -> RequestContext {
    let mut headers = http::HeaderMap::new();
    headers.insert("cookie", session_cookie.parse().unwrap());
    let mut ctx = RequestContext::new(headers);
    ctx.extensions_mut().insert(TenantId(tenant_id.to_string()));
    ctx
}

fn consent_context(tenant_id: &str, public_subject: &str) -> RequestContext {
    let mut ctx = RequestContext::new(http::HeaderMap::new());
    ctx.extensions_mut().insert(AuthContext {
        tenant_id: tenant_id.to_string(),
        subject: public_subject.to_string(),
        subject_type: SubjectType::User,
        actor: None,
        scopes: vec!["tenant:admin".to_string()],
        token_hash: "hash".to_string(),
        authentication_methods: Vec::new(),
    });
    ctx.extensions_mut().insert(TenantId(tenant_id.to_string()));
    ctx
}

async fn create_tenant(pool: &sqlx::PgPool) -> String {
    let tenant_id = ulid::Ulid::new().to_string();
    sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
        .bind(&tenant_id)
        .bind(format!("t-{}", tenant_id.to_lowercase()))
        .bind("First-Use Test Tenant")
        .execute(pool)
        .await
        .expect("tenant should be created");
    tenant_id
}

struct User {
    public_subject: String,
    session_cookie: String,
}

const TEST_PASSWORD: &str = "FirstUse-Test-Pass-123!";

async fn create_user(svc: &Services, tenant_id: &str, email: &str) -> User {
    // Kratos identities are unique by email and the container is shared
    // across feature modules, so mint a unique address per user.
    let (local, domain) = email.split_once('@').expect("email should contain @");
    let unique = format!(
        "{}+{}@{}",
        local,
        ulid::Ulid::new().to_string().to_lowercase(),
        domain
    );
    let flow = svc
        .kratos
        .create_registration_flow(&[])
        .await
        .expect("registration flow should be created");
    let flow_id = flow["id"].as_str().expect("flow id").to_string();
    let submitted = svc
        .kratos
        .submit_registration_flow(
            &flow_id,
            None,
            json!({
                "method": "password",
                "password": TEST_PASSWORD,
                "traits": { "email": unique }
            }),
        )
        .await
        .expect("registration should succeed");
    let identity_id = submitted.body["identity"]["id"]
        .as_str()
        .expect("identity id")
        .to_string();
    let public_subject = ulid::Ulid::new().to_string();
    IdMappingStore::create(
        &svc.mappings,
        tenant_id,
        "kratos",
        &public_subject,
        &identity_id,
    )
    .await
    .expect("identity mapping should be created");
    // The login gate validates a browser cookie; Kratos v25 session cookies
    // are NOT the API session token, so log in through the browser flow to
    // obtain a real `ory_kratos_session` cookie value.
    let session_cookie = browser_login_cookie(svc, &unique).await;
    User {
        public_subject,
        session_cookie,
    }
}

/// Log in through Kratos' browser login flow and return the
/// `ory_kratos_session=<value>` cookie pair.
async fn browser_login_cookie(svc: &Services, email: &str) -> String {
    let kratos_public = svc.kratos_public_url.clone();
    let http = no_redirect_client();
    let resp = http
        .get(format!("{kratos_public}/self-service/login/browser"))
        .send()
        .await
        .expect("browser login flow should start");
    let location = resp
        .headers()
        .get("location")
        .and_then(|h| h.to_str().ok())
        .expect("browser login flow should redirect")
        .to_string();
    let flow_id = extract_query_param(&location, "flow").expect("flow id should be present");
    let flow: Value = http
        .get(format!("{kratos_public}/self-service/login/flows"))
        .query(&[("id", flow_id.as_str())])
        .header("accept", "application/json")
        .send()
        .await
        .expect("login flow should fetch")
        .json()
        .await
        .expect("login flow should be json");
    let csrf = flow["ui"]["nodes"]
        .as_array()
        .expect("flow nodes")
        .iter()
        .find(|n| n["attributes"]["name"].as_str() == Some("csrf_token"))
        .and_then(|n| n["attributes"]["value"].as_str())
        .expect("csrf token")
        .to_string();
    let resp = http
        .post(format!("{kratos_public}/self-service/login"))
        .query(&[("flow", flow_id.as_str())])
        .header("accept", "application/json")
        .json(&json!({
            "method": "password",
            "identifier": email,
            "password": TEST_PASSWORD,
            "csrf_token": csrf,
        }))
        .send()
        .await
        .expect("login submit should complete");
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|cookie| {
            let pair = cookie.split(';').next()?;
            pair.starts_with("ory_kratos_session=")
                .then(|| pair.to_string())
        })
        .expect("login should set the ory_kratos_session cookie")
}

struct Client {
    ory_client_id: String,
    client_secret: String,
    public_id: String,
}

/// A DCR-shaped client: Hydra client + mapping, and (for `source = Some(..)`)
/// an applications row. `source = None` leaves it provisional.
async fn register_client(svc: &Services, tenant_id: &str, source: Option<&str>) -> Client {
    let created = svc
        .hydra
        .create_oauth2_client(json!({
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": "openid offline_access",
            "redirect_uris": [REDIRECT_URI],
            "token_endpoint_auth_method": "client_secret_post",
        }))
        .await
        .expect("hydra client should be created");
    let ory_client_id = created["client_id"]
        .as_str()
        .expect("client_id")
        .to_string();
    let client_secret = created["client_secret"]
        .as_str()
        .expect("client_secret")
        .to_string();
    let public_id = ulid::Ulid::new().to_string();
    IdMappingStore::create(
        &svc.mappings,
        tenant_id,
        "hydra",
        &public_id,
        &ory_client_id,
    )
    .await
    .expect("client mapping should be created");
    if let Some(source) = source {
        svc.applications
            .create(tenant_id, &public_id, false, source)
            .await
            .expect("applications row should be created");
    }
    Client {
        ory_client_id,
        client_secret,
        public_id,
    }
}

/// Start an authorization request and return Hydra's login challenge.
async fn start_authorize(svc: &Services, http: &reqwest::Client, client: &Client) -> String {
    let resp = http
        .get(format!("{}/oauth2/auth", svc.hydra_public_url))
        .query(&[
            ("response_type", "code"),
            ("client_id", client.ory_client_id.as_str()),
            ("redirect_uri", REDIRECT_URI),
            ("scope", "openid offline_access"),
            ("state", "first-use-state"),
        ])
        .send()
        .await
        .expect("authorize request should complete");
    assert!(
        resp.status().is_redirection(),
        "authorize should redirect to login: {:?}",
        resp.status()
    );
    let location = resp
        .headers()
        .get("location")
        .and_then(|h| h.to_str().ok())
        .expect("login location should exist");
    extract_query_param(location, "login_challenge").expect("login_challenge should be present")
}

/// Run the login gate. On success returns the Hydra `redirect_to` to follow.
async fn run_login_gate(
    svc: &Services,
    tenant_id: &str,
    user: &User,
    login_challenge: &str,
) -> Result<String, connectrpc::ConnectError> {
    let ctx = login_context(tenant_id, &user.session_cookie);
    let req = service_request(CreateLoginFlowRequest {
        login_challenge: login_challenge.to_string(),
        ..Default::default()
    });
    svc.self_service
        .create_login_flow(ctx, req)
        .await
        .map(|resp| resp.body.redirect_browser_to)
}

/// Follow the accepted-login redirect and return the consent challenge.
async fn consent_challenge_after_login(
    svc: &Services,
    http: &reqwest::Client,
    redirect: &str,
) -> String {
    let url = rewrite_hydra_origin(redirect, &svc.hydra_public_url);
    let resp = http.get(url).send().await.expect("login verifier leg");
    assert!(
        resp.status().is_redirection(),
        "after login should redirect to consent: {:?}",
        resp.status()
    );
    let location = resp
        .headers()
        .get("location")
        .and_then(|h| h.to_str().ok())
        .expect("consent location should exist");
    extract_query_param(location, "consent_challenge").expect("consent_challenge should be present")
}

/// Whether GetConsentRequest flags this consent as a first use.
async fn first_use_flag(svc: &Services, tenant_id: &str, user: &User, challenge: &str) -> bool {
    let ctx = consent_context(tenant_id, &user.public_subject);
    let req = service_request(GetChallengeRequest {
        challenge: challenge.to_string(),
        ..Default::default()
    });
    svc.consent
        .get_consent_request(ctx, req)
        .await
        .expect("get_consent_request should succeed")
        .body
        .first_use
}

/// Run the consent gate. On success returns the consent `redirect_to`.
async fn run_consent_gate(
    svc: &Services,
    tenant_id: &str,
    user: &User,
    consent_challenge: &str,
) -> Result<String, connectrpc::ConnectError> {
    let ctx = consent_context(tenant_id, &user.public_subject);
    let req = service_request(AcceptConsentRequest {
        challenge: consent_challenge.to_string(),
        grant_scope: vec!["openid".to_string()],
        ..Default::default()
    });
    svc.consent
        .accept_consent(ctx, req)
        .await
        .map(|resp| resp.body.redirect_to)
}

/// Follow the accepted-consent redirect and exchange the code for tokens.
async fn finish_flow(
    svc: &Services,
    http: &reqwest::Client,
    client: &Client,
    redirect: &str,
) -> Value {
    let url = rewrite_hydra_origin(redirect, &svc.hydra_public_url);
    let resp = http.get(url).send().await.expect("consent verifier leg");
    assert!(
        resp.status().is_redirection(),
        "consent accept should redirect to the client: {:?}",
        resp.status()
    );
    let location = resp
        .headers()
        .get("location")
        .and_then(|h| h.to_str().ok())
        .expect("final location should exist");
    assert!(
        location.starts_with(REDIRECT_URI),
        "final redirect must target the client redirect_uri: {location}"
    );
    let code = extract_query_param(location, "code")
        .unwrap_or_else(|| panic!("code should be present in redirect: {location}"));

    svc.http_token(&code, client).await
}

impl Services {
    async fn http_token(&self, code: &str, client: &Client) -> Value {
        let resp = reqwest::Client::new()
            .post(format!("{}/oauth2/token", self.hydra_public_url))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", REDIRECT_URI),
                ("client_id", client.ory_client_id.as_str()),
                ("client_secret", client.client_secret.as_str()),
            ])
            .send()
            .await
            .expect("token exchange should succeed");
        let status = resp.status();
        let body: Value = resp.json().await.expect("token response should be json");
        assert!(
            status.is_success(),
            "token exchange failed: {status} {body}"
        );
        body
    }
}

/// Drive one full anonymous-DCR-style journey: authorize → login gate →
/// consent gate → token.
async fn full_flow(svc: &Services, tenant_id: &str, user: &User, client: &Client) -> Value {
    let http = no_redirect_client();
    let login_challenge = start_authorize(svc, &http, client).await;
    let redirect = run_login_gate(svc, tenant_id, user, &login_challenge)
        .await
        .expect("login gate should pass");
    let consent_challenge = consent_challenge_after_login(svc, &http, &redirect).await;
    let consent_redirect = run_consent_gate(svc, tenant_id, user, &consent_challenge)
        .await
        .expect("consent gate should pass");
    finish_flow(svc, &http, client, &consent_redirect).await
}

/// Assert a token response carries an access token.
fn assert_token_issued(token: &Value) {
    assert!(
        !token["access_token"]
            .as_str()
            .unwrap_or_default()
            .is_empty(),
        "token should be issued: {token}"
    );
}

/// Count `member` tuples for one subject on the application object. OpenFGA
/// stores user subjects typed (`user:<id>`); Keto stores them raw.
async fn member_tuple_count(svc: &Services, tenant_id: &str, app: &str, subject: &str) -> usize {
    let typed = format!("user:{subject}");
    svc.backend
        .read_tuples(tenant_id, ENTITLEMENT_NAMESPACE, app)
        .await
        .expect("tuples should read")
        .iter()
        .filter(|t| t.relation == "member" && (t.subject_id == subject || t.subject_id == typed))
        .count()
}

/// SSO-039 full journey: anonymous DCR → login defers to consent →
/// interactive consent grants the consenting user → token issued → second
/// login passes with no grant duplication → a second user is consent-gated
/// too and granted per-user.
async fn first_use_journey(svc: &Services) {
    let _guard = FLOW_LOCK.lock().await;
    let tenant = create_tenant(&svc.pool).await;
    let user1 = create_user(svc, &tenant, "user1@example.com").await;
    let user2 = create_user(svc, &tenant, "user2@example.com").await;
    let client = register_client(svc, &tenant, None).await; // provisional

    // First use: the consent step is flagged as first-use and grants user1.
    let http = no_redirect_client();
    let login_challenge = start_authorize(svc, &http, &client).await;
    let redirect = run_login_gate(svc, &tenant, &user1, &login_challenge)
        .await
        .expect("provisional client must defer to consent, not 403");
    let consent_challenge = consent_challenge_after_login(svc, &http, &redirect).await;
    assert!(
        first_use_flag(svc, &tenant, &user1, &consent_challenge).await,
        "first consent must be flagged first_use"
    );
    let consent_redirect = run_consent_gate(svc, &tenant, &user1, &consent_challenge)
        .await
        .expect("interactive first-use consent should grant");
    let token = finish_flow(svc, &http, &client, &consent_redirect).await;
    assert_token_issued(&token);

    // The grant exists and is per-user; the DCR row was created.
    assert_eq!(
        member_tuple_count(svc, &tenant, &client.public_id, &user1.public_subject).await,
        1
    );
    let row = svc
        .applications
        .get(&tenant, &client.public_id)
        .await
        .expect("first use must create the applications row");
    assert_eq!(row.registration_source, REGISTRATION_SOURCE_DCR);
    // The mapping was already home; no cross-tenant move happened.
    assert_eq!(
        svc.mappings
            .get_tenant_id_by_ory_id("hydra", &client.ory_client_id)
            .await
            .unwrap()
            .as_deref(),
        Some(tenant.as_str())
    );

    // Second login by the same user: entitled, no consent decision, no
    // duplicate grant.
    let token2 = full_flow(svc, &tenant, &user1, &client).await;
    assert_token_issued(&token2);
    assert_eq!(
        member_tuple_count(svc, &tenant, &client.public_id, &user1.public_subject).await,
        1,
        "second login must not duplicate the grant"
    );

    // Second user through the same client: consent-gated again (per-user
    // model), granted per-user.
    let http2 = no_redirect_client();
    let login_challenge2 = start_authorize(svc, &http2, &client).await;
    let redirect2 = run_login_gate(svc, &tenant, &user2, &login_challenge2)
        .await
        .expect("second user should also defer to consent");
    let consent_challenge2 = consent_challenge_after_login(svc, &http2, &redirect2).await;
    assert!(
        first_use_flag(svc, &tenant, &user2, &consent_challenge2).await,
        "the second user's consent is THEIR first use"
    );
    let consent_redirect2 = run_consent_gate(svc, &tenant, &user2, &consent_challenge2)
        .await
        .expect("second user's interactive consent should grant");
    finish_flow(svc, &http2, &client, &consent_redirect2).await;
    assert_eq!(
        member_tuple_count(svc, &tenant, &client.public_id, &user2.public_subject).await,
        1
    );
    // Never a group link: only the two per-user member tuples exist.
    let tuples = svc
        .backend
        .read_tuples(&tenant, ENTITLEMENT_NAMESPACE, &client.public_id)
        .await
        .expect("tuples should read");
    assert!(
        tuples.iter().all(|t| !t.subject_id.contains("employees")),
        "first use must never write group links: {tuples:?}"
    );
}

/// SSO-039 ownership: a provisional client mapped in another tenant is
/// claimed (mapping re-homed) by the first consenting user's tenant.
async fn provisional_claim(svc: &Services) {
    let _guard = FLOW_LOCK.lock().await;
    let tenant_a = create_tenant(&svc.pool).await;
    let tenant_b = create_tenant(&svc.pool).await;
    let client = register_client(svc, &tenant_a, None).await; // provisional in A
    let user_b = create_user(svc, &tenant_b, "user-b@example.com").await;

    let token = full_flow(svc, &tenant_b, &user_b, &client).await;
    assert_token_issued(&token);
    assert_eq!(
        svc.mappings
            .get_tenant_id_by_ory_id("hydra", &client.ory_client_id)
            .await
            .unwrap()
            .as_deref(),
        Some(tenant_b.as_str()),
        "mapping must be re-homed to the consenting tenant"
    );
    let row = svc
        .applications
        .get(&tenant_b, &client.public_id)
        .await
        .expect("row must be created in the consenting tenant");
    assert_eq!(row.registration_source, REGISTRATION_SOURCE_DCR);
    assert_eq!(
        member_tuple_count(svc, &tenant_b, &client.public_id, &user_b.public_subject).await,
        1
    );
}

/// SSO-039 fail-closed: a user of tenant B is denied at login for a client
/// owned by tenant A (its applications row lives there).
async fn cross_tenant_denial(svc: &Services) {
    let _guard = FLOW_LOCK.lock().await;
    let tenant_a = create_tenant(&svc.pool).await;
    let tenant_b = create_tenant(&svc.pool).await;
    let client = register_client(svc, &tenant_a, Some(REGISTRATION_SOURCE_DCR)).await;
    let user_b = create_user(svc, &tenant_b, "user-c@example.com").await;

    let http = no_redirect_client();
    let login_challenge = start_authorize(svc, &http, &client).await;
    let err = run_login_gate(svc, &tenant_b, &user_b, &login_challenge)
        .await
        .expect_err("cross-tenant-owned client must deny at login");
    assert_eq!(err.code, ErrorCode::PermissionDenied);
    assert!(
        err.message
            .as_deref()
            .unwrap_or_default()
            .contains("different organization"),
        "unexpected error message: {err:?}"
    );
    // Zero state changes in tenant B.
    assert!(
        svc.applications
            .get(&tenant_b, &client.public_id)
            .await
            .is_err()
    );
    assert_eq!(
        svc.mappings
            .get_tenant_id_by_ory_id("hydra", &client.ory_client_id)
            .await
            .unwrap()
            .as_deref(),
        Some(tenant_a.as_str())
    );
}

/// Regression: an admin-registered application still hard-403s at login for
/// unentitled users.
async fn admin_app_denial(svc: &Services) {
    let _guard = FLOW_LOCK.lock().await;
    let tenant = create_tenant(&svc.pool).await;
    let client = register_client(svc, &tenant, Some(REGISTRATION_SOURCE_ADMIN)).await;
    let user = create_user(svc, &tenant, "user-d@example.com").await;

    let http = no_redirect_client();
    let login_challenge = start_authorize(svc, &http, &client).await;
    let err = run_login_gate(svc, &tenant, &user, &login_challenge)
        .await
        .expect_err("admin app must deny unentitled users at login");
    assert_eq!(err.code, ErrorCode::PermissionDenied);
    assert!(
        err.message
            .as_deref()
            .unwrap_or_default()
            .contains("not entitled"),
        "unexpected error message: {err:?}"
    );
    assert_eq!(
        member_tuple_count(svc, &tenant, &client.public_id, &user.public_subject).await,
        0,
        "a denied login writes no tuples"
    );
}

/// Decode a JWT payload without verifying the signature (the token came
/// straight from the Hydra container this test drives).
fn jwt_payload(id_token: &str) -> Value {
    use base64::Engine;
    let segment = id_token.split('.').nth(1).expect("jwt payload segment");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .expect("jwt payload should decode");
    serde_json::from_slice(&bytes).expect("jwt payload should be json")
}

/// SSO-039 cross_tenant semantics: a foreign user explicitly granted in the
/// OWNER tenant on a `cross_tenant=true` app passes both gates; the grant
/// tuple and the minted claim live in the owner tenant only.
async fn cross_tenant_granted_user_passes(svc: &Services) {
    let _guard = FLOW_LOCK.lock().await;
    let tenant_a = create_tenant(&svc.pool).await;
    let tenant_b = create_tenant(&svc.pool).await;
    let client = register_client(svc, &tenant_a, Some(REGISTRATION_SOURCE_ADMIN)).await;
    svc.applications
        .set_cross_tenant(&tenant_a, &client.public_id, true)
        .await
        .expect("cross_tenant flag should be set");
    let user_b = create_user(svc, &tenant_b, "foreign-granted@example.com").await;
    // Explicit per-user grant in the OWNER tenant, referencing the foreign
    // user's public ULID.
    svc.entitlements
        .grant(
            &tenant_a,
            &user_b.public_subject,
            &client.public_id,
            EntitlementLevel::Member,
        )
        .await
        .expect("grant should succeed");

    let token = full_flow(svc, &tenant_b, &user_b, &client).await;
    assert_token_issued(&token);

    // The claim is minted from the owner tenant's entitlement store.
    let id_token = token["id_token"].as_str().expect("id_token should exist");
    let payload = jwt_payload(id_token);
    assert_eq!(
        payload["entitlements"][&client.public_id],
        json!(["member"]),
        "claim should be minted from the owner tenant: {payload}"
    );

    // The grant tuple lives in the owner tenant; tenant B got zero writes.
    assert_eq!(
        member_tuple_count(svc, &tenant_a, &client.public_id, &user_b.public_subject).await,
        1
    );
    assert_eq!(
        member_tuple_count(svc, &tenant_b, &client.public_id, &user_b.public_subject).await,
        0
    );
    assert!(
        svc.applications
            .get(&tenant_b, &client.public_id)
            .await
            .is_err()
    );
    assert_eq!(
        svc.mappings
            .get_tenant_id_by_ory_id("hydra", &client.ory_client_id)
            .await
            .unwrap()
            .as_deref(),
        Some(tenant_a.as_str()),
        "an owned app is never re-homed"
    );
}

/// A `cross_tenant=false` app still fails closed for foreign users even when
/// a (meaningless) tuple exists in the owner tenant.
async fn cross_tenant_flag_off_denies(svc: &Services) {
    let _guard = FLOW_LOCK.lock().await;
    let tenant_a = create_tenant(&svc.pool).await;
    let tenant_b = create_tenant(&svc.pool).await;
    let client = register_client(svc, &tenant_a, Some(REGISTRATION_SOURCE_ADMIN)).await;
    let user_b = create_user(svc, &tenant_b, "foreign-flag-off@example.com").await;
    svc.entitlements
        .grant(
            &tenant_a,
            &user_b.public_subject,
            &client.public_id,
            EntitlementLevel::Member,
        )
        .await
        .expect("grant should succeed");

    let http = no_redirect_client();
    let login_challenge = start_authorize(svc, &http, &client).await;
    let err = run_login_gate(svc, &tenant_b, &user_b, &login_challenge)
        .await
        .expect_err("unflagged cross-tenant-owned client must deny at login");
    assert_eq!(err.code, ErrorCode::PermissionDenied);
    assert!(
        err.message
            .as_deref()
            .unwrap_or_default()
            .contains("different organization"),
        "unexpected error message: {err:?}"
    );
}

/// A foreign user WITHOUT a grant on a `cross_tenant=true` app gets the
/// plain "not entitled" denial — never a first-use grant — and zero writes
/// land in either tenant.
async fn cross_tenant_ungranted_user_denied(svc: &Services) {
    let _guard = FLOW_LOCK.lock().await;
    let tenant_a = create_tenant(&svc.pool).await;
    let tenant_b = create_tenant(&svc.pool).await;
    let client = register_client(svc, &tenant_a, Some(REGISTRATION_SOURCE_ADMIN)).await;
    svc.applications
        .set_cross_tenant(&tenant_a, &client.public_id, true)
        .await
        .expect("cross_tenant flag should be set");
    let user_b = create_user(svc, &tenant_b, "foreign-ungranted@example.com").await;

    let http = no_redirect_client();
    let login_challenge = start_authorize(svc, &http, &client).await;
    let err = run_login_gate(svc, &tenant_b, &user_b, &login_challenge)
        .await
        .expect_err("ungranted foreign user must be denied");
    assert_eq!(err.code, ErrorCode::PermissionDenied);
    assert!(
        err.message
            .as_deref()
            .unwrap_or_default()
            .contains("not entitled"),
        "flagged cross-tenant denial uses the plain message: {err:?}"
    );
    // Zero writes in either tenant.
    assert_eq!(
        member_tuple_count(svc, &tenant_a, &client.public_id, &user_b.public_subject).await,
        0
    );
    assert_eq!(
        member_tuple_count(svc, &tenant_b, &client.public_id, &user_b.public_subject).await,
        0
    );
    assert!(
        svc.applications
            .get(&tenant_b, &client.public_id)
            .await
            .is_err()
    );
}

#[cfg(feature = "openfga")]
mod openfga {
    use super::*;
    use sso_gateway::db::PgPermissionNamespaceStore;
    use sso_gateway::services::permission::OpenFgaPermissionBackend;
    use sso_openfga_client::OpenFgaClient;

    static OPENFGA: tokio::sync::OnceCell<(ContainerAsync<GenericImage>, String)> =
        tokio::sync::OnceCell::const_new();

    async fn openfga_url() -> String {
        let (_, url) = OPENFGA
            .get_or_init(|| async {
                support::start_openfga()
                    .await
                    .expect("openfga should start")
            })
            .await;
        url.clone()
    }

    async fn services() -> Services {
        let url = openfga_url().await;
        let shared = shared().await;
        let pool = create_pool(&shared.database_url, false)
            .await
            .expect("database pool should be created");
        let client = OpenFgaClient::new(&url).expect("openfga client should build");
        let backend: Arc<dyn PermissionBackend> = Arc::new(OpenFgaPermissionBackend::new(
            client,
            Arc::new(PgPermissionNamespaceStore::new(pool)),
        ));
        build_services(backend).await
    }

    #[tokio::test]
    async fn first_use_journey_openfga() {
        first_use_journey(&services().await).await;
    }

    #[tokio::test]
    async fn provisional_claim_openfga() {
        provisional_claim(&services().await).await;
    }

    #[tokio::test]
    async fn cross_tenant_denial_openfga() {
        cross_tenant_denial(&services().await).await;
    }

    #[tokio::test]
    async fn admin_app_denial_openfga() {
        admin_app_denial(&services().await).await;
    }

    #[tokio::test]
    async fn cross_tenant_granted_user_passes_openfga() {
        cross_tenant_granted_user_passes(&services().await).await;
    }

    #[tokio::test]
    async fn cross_tenant_flag_off_denies_openfga() {
        cross_tenant_flag_off_denies(&services().await).await;
    }

    #[tokio::test]
    async fn cross_tenant_ungranted_user_denied_openfga() {
        cross_tenant_ungranted_user_denied(&services().await).await;
    }
}

#[cfg(feature = "keto")]
mod keto {
    use super::*;
    use sso_ory_client::KetoClient;

    static KETO: tokio::sync::OnceCell<(ContainerAsync<GenericImage>, String, String)> =
        tokio::sync::OnceCell::const_new();

    async fn keto_urls() -> (String, String) {
        let (_, read_url, write_url) = KETO
            .get_or_init(|| async { support::start_keto().await.expect("keto should start") })
            .await;
        (read_url.clone(), write_url.clone())
    }

    async fn services() -> Services {
        let (read_url, write_url) = keto_urls().await;
        let backend: Arc<dyn PermissionBackend> =
            Arc::new(KetoClient::new(&read_url, &write_url).expect("keto client should build"));
        build_services(backend).await
    }

    #[tokio::test]
    async fn first_use_journey_keto() {
        first_use_journey(&services().await).await;
    }

    #[tokio::test]
    async fn provisional_claim_keto() {
        provisional_claim(&services().await).await;
    }

    #[tokio::test]
    async fn cross_tenant_denial_keto() {
        cross_tenant_denial(&services().await).await;
    }

    #[tokio::test]
    async fn admin_app_denial_keto() {
        admin_app_denial(&services().await).await;
    }

    #[tokio::test]
    async fn cross_tenant_granted_user_passes_keto() {
        cross_tenant_granted_user_passes(&services().await).await;
    }

    #[tokio::test]
    async fn cross_tenant_flag_off_denies_keto() {
        cross_tenant_flag_off_denies(&services().await).await;
    }

    #[tokio::test]
    async fn cross_tenant_ungranted_user_denied_keto() {
        cross_tenant_ungranted_user_denied(&services().await).await;
    }
}
