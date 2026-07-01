# HRD / SSO Universal Login Plan

## Objective

Add a single, tenant-aware login entry point to `sso-gateway` that supports:

- Corporate tenants that bring their own IdP (SAML 2.0 or OIDC).
- Sunbeam-managed tenants that use local credentials.
- Personal accounts with consumer email domains.

The flow is driven by **Home Realm Discovery (HRD)**: an internal module takes
an email and decides the correct authentication method, returning a
backend-driven redirect. No tenant-specific branding, no custom tenant URLs, and
no public tenant enumeration. The HRD module is internal to the gateway; the
public frontend never invokes it directly.

## Success Criteria

- The HRD module returns a backend-driven redirect for every email input.
- Unknown and consumer-domain emails receive the exact same response shape as
  known corporate emails.
- All new code has **>90% region and line coverage**.
- Product documentation is updated to describe the universal login flow,
  connection configuration, and IdP setup.
- Existing tests continue to pass after the changes.

## Non-Goals

- Custom tenant branding on the login page.
- Vanity subdomains or path-based tenant URLs.
- Magic links as the primary login mechanism.

## Architecture

```text
┌─────────────┐     email      ┌─────────────────────┐
│   Browser   │ ─────────────> │ Public login        │
│  login page │                │ handler (REST/RPC)  │
└─────────────┘                └──────────┬──────────┘
                                          │
                                          ▼
                              ┌───────────────────────┐
                              │    hrd::discover      │
                              │   (internal module)   │
                              └───────────┬───────────┘
                                          │
                              ┌───────────┼───────────┐
                              ▼           ▼           ▼
                       ┌──────────┐ ┌──────────┐ ┌────────────┐
                       │  OIDC    │ │  SAML    │ │  local     │
                       │ redirect │ │ redirect │ │ login page │
                       └────┬─────┘ └────┬─────┘ └─────┬──────┘
                            │            │             │
                            ▼            ▼             ▼
                     IdP authorization IdP SAML   IdentitySelfService
                     + callback       + callback  code/password flows
```

## Data Model

### New table: `tenant_connections`

Domain-based IdP connections. `domain` is required and must be a verified
custom domain.

| column | type | notes |
|---|---|---|
| `id` | `text` | primary key, ULID |
| `tenant_id` | `text` | FK → `tenants(id)` |
| `connection_type` | `text` | `oidc`, `oauth2`, or `saml` |
| `domain` | `text` | verified custom email domain |
| `config` | `jsonb` | IdP-specific configuration |
| `is_enabled` | `bool` | soft-disable a connection |
| `created_at` | `timestamptz` | |
| `updated_at` | `timestamptz` | |

Constraints:

- `UNIQUE (domain)` — one connection per verified domain.
- `CHECK (connection_type IN ('oidc','oauth2','saml'))`
- `CHECK (domain IS NOT NULL)`

### New table: `tenant_local_auth`

Local credential methods. No domain; looked up by `tenant_id` after tenant
selection.

| column | type | notes |
|---|---|---|
| `id` | `text` | primary key, ULID |
| `tenant_id` | `text` | FK → `tenants(id)` |
| `method` | `text` | `password` or `code` |
| `config` | `jsonb` | method-specific settings |
| `is_enabled` | `bool` | soft-disable a method |
| `created_at` | `timestamptz` | |
| `updated_at` | `timestamptz` | |

Constraints:

- `UNIQUE (tenant_id, method)` — one of each local method per tenant.
- `CHECK (method IN ('password','code'))`

Local auth methods are soft-deleted via `is_enabled = false`; rows are never
hard-deleted so they can be re-enabled if an external IdP fails. There is no
requirement that a tenant keep at least one active auth method, since some
enterprises require a single external IdP for compliance.

### New table: `tenant_domains`

Tracks custom-domain verification for tenants.

| column | type | notes |
|---|---|---|
| `id` | `text` | primary key, ULID |
| `tenant_id` | `text` | FK → `tenants(id)` |
| `domain` | `text` | domain being verified |
| `verification_token` | `text` | random token for DNS TXT record |
| `is_verified` | `bool` | set after successful DNS check |
| `verified_at` | `timestamptz?` | |
| `created_at` | `timestamptz` | |
| `updated_at` | `timestamptz` | |

Constraints:

- `UNIQUE (domain)` — one tenant can claim a given domain.

### Config schemas

**`oidc`**

```json
{
  "issuer": "https://accounts.google.com",
  "client_id": "...",
  "client_secret": "...",
  "scopes": ["openid", "email", "profile"],
  "redirect_uri": "https://gateway.example.com/auth/callback/oidc"
}
```

**`oauth2`**

```json
{
  "authorization_url": "https://github.com/login/oauth/authorize",
  "token_url": "https://github.com/login/oauth/access_token",
  "userinfo_url": "https://api.github.com/user",
  "userinfo_email_path": "email",
  "client_id": "...",
  "client_secret": "...",
  "scopes": ["user:email"],
  "redirect_uri": "https://gateway.example.com/auth/callback/oauth2"
}
```

Used for social or legacy providers that do not publish an OpenID Connect
issuer (e.g., GitHub, Slack, X/Twitter). The callback exchanges the code for an
access token, calls `userinfo_url`, and extracts the email using
`userinfo_email_path`.

**`saml`**

```json
{
  "provider_id": "<existing saml_providers.id>"
}
```

Reuses the existing `saml_providers` table for metadata, certificates, etc.

**`password` / `code`** (in `tenant_local_auth.config`)

```json
{}
```

Actual credential storage and verification is delegated to Kratos.

### Bootstrap change

- `bootstrap_system_tenant` creates the system tenant for gateway administrators.
  The system tenant is otherwise a normal tenant: it can use local auth
  (`password`/`code`) or a verified custom-domain connection just like any other
  tenant. Its distinguishing feature is administrative access to tenant CRUD and
  other system-level operations, enforced through Keto on top of the standard
  authentication flows.
- There is **no catch-all tenant**. Every tenant is distinct. A tenant may be a
  single person with a `@gmail.com` address or a company with a custom domain.
- Tenant creation is gated by the global `registration_enabled` config flag.

### Domain verification flow

1. Admin requests verification for `example.com`.
2. Gateway generates a token and stores it in `tenant_domains`.
3. Admin creates a DNS TXT record at the root of `example.com`:
   ```
   sunbeam-verify=<token>
   ```
4. Gateway polls or verifies on demand; if the TXT record matches, the domain
   is marked verified.
5. Only verified domains can be used in `tenant_connections`.

## HRD Module

```rust
pub enum DiscoveryResult {
    Oidc(OidcRedirect),
    OAuth2(OAuth2Redirect),
    Saml(SamlRedirect),
    SelectTenant(TenantSelectionRedirect),
}

pub struct OidcRedirect {
    pub authorization_url: String,
}

pub struct OAuth2Redirect {
    pub authorization_url: String,
}

pub struct SamlRedirect {
    pub sso_url: String,
    pub saml_request: String, // Base64-encoded AuthnRequest
    pub relay_state: String,
}

pub struct TenantSelectionRedirect {
    pub redirect_url: String,
}
```

The `hrd::discover` function is an internal module call. It takes an email and
a `return_to` URL and returns a `DiscoveryResult`. It is never exposed to the
browser.

### Behavior

1. Parse the email domain.
2. Query `tenant_connections` for an enabled row matching the domain.
   - A match is only possible for **verified custom domains**.
   - Consumer domains (`gmail.com`, `outlook.com`, etc.) never match because
     they cannot be verified.
3. If a match is found:
   - `oidc`  → build the IdP authorization URL and return `OidcRedirect`.
   - `oauth2` → build the provider authorization URL and return `OAuth2Redirect`.
   - `saml`  → build the SAML `AuthnRequest` and return `SamlRedirect`.
   - `code` / `password` are never returned by HRD because local auth has no
     domain; users reach local auth through tenant selection.
4. If no match is found:
   - Return `SelectTenant` to
     `/login/select-tenant?email=alice@gmail.com&return_to=<url>`.
     The user must enter an existing tenant slug or create a new tenant.

The response shape is always `DiscoveryResult`, so an attacker probing emails
cannot tell from the response whether a domain is configured.

### Tenant selection page

Route: `/login/select-tenant?email=...&return_to=...`

- Input field for **tenant slug**.
- “Continue” looks up the tenant and redirects to its configured local login or
  SSO connection.
- If `registration_enabled` is true, a “Create workspace” button starts the
  tenant creation flow. The new tenant can then configure `code` or `password`
  local auth.
- If the user already knows their tenant slug, they can skip HRD entirely and go
  directly to `/login/local?tenant_id=<slug>&method=...`.

SAML connections require a verified custom domain. `oidc` and `oauth2` social
providers can be configured by any tenant, including consumer-domain tenants,
but they are only reached via tenant selection, not domain-based HRD. SCIM is
out of scope for this plan but follows the same custom-domain rule.

## Authentication Flows

### Local code / password

The SPA at `/login/local` reads `tenant_id` and `method` from the query string
and calls the existing `IdentitySelfService` RPCs:

1. Look up `tenant_local_auth` for the tenant to confirm the method is enabled.
2. `IdentitySelfService/CreateLoginFlow` with `x-tenant-id`.
3. Render password field or code prompt based on `method`.
4. `IdentitySelfService/SubmitLoginFlow`.
   - For an existing identity, authentication proceeds normally.
   - For a new identity, creation is allowed only if `registration_enabled` is
     true **and** the tenant allows self-registration.
5. Gateway cookie middleware resolves tenant from the Kratos session via
   `id_mappings`.

### OIDC

1. HRD builds the authorization URL from the provider’s
   `/.well-known/openid-configuration`.
2. State is generated as a signed token containing `tenant_id`, `connection_id`,
   `nonce`, and `return_to`. It is stored in a short-lived, `HttpOnly`, `Secure`,
   `SameSite=Lax` cookie.
3. Browser authenticates at the IdP.
4. IdP redirects to `/auth/callback/oidc`.
5. Gateway verifies the state signature, extracts `tenant_id` and
   `connection_id`, and loads the connection config.
6. Gateway exchanges the code for tokens, validates the ID token, and extracts
   the email.
7. Gateway looks up or creates the Kratos identity by email.
8. Tenant is resolved via `id_mappings`. If no mapping exists and the tenant
   permits registration, a new mapping is created; otherwise the request fails.
9. `return_to` is validated against the tenant's verified domain (or the global
   frontend allow-list for consumer-domain tenants) and the browser is
   redirected.

### OAuth2 (social / legacy)

1. HRD builds the authorization URL from the configured `authorization_url`,
   `client_id`, `scopes`, and `redirect_uri`.
2. State is generated as a signed token containing `tenant_id`, `connection_id`,
   and `return_to`. It is stored in a short-lived, `HttpOnly`, `Secure`,
   `SameSite=Lax` cookie. Nonce is not used because OAuth2 has no ID token.
3. Browser authenticates at the provider.
4. Provider redirects to `/auth/callback/oauth2`.
5. Gateway verifies the state signature, extracts `tenant_id` and
   `connection_id`, and loads the connection config.
6. Gateway exchanges the code for an access token.
7. Gateway calls `userinfo_url` and extracts the email using
   `userinfo_email_path`.
8. Same identity lookup, tenant resolution, session steps, and `return_to`
   validation as OIDC.

### SAML

1. HRD verifies the matched connection is for a **verified custom domain**.
   Consumer-domain tenants cannot configure `saml`.
2. HRD looks up the existing `saml_providers` row by `provider_id`.
3. Gateway builds and signs a SAML `AuthnRequest`, Base64-encodes it, and
   returns the IdP SSO URL in the response.
4. State/RelayState is generated as a signed token containing `tenant_id`,
   `connection_id`, and `return_to`.
5. IdP redirects to `/auth/callback/saml` with a SAML response.
6. Gateway verifies the RelayState signature, extracts `tenant_id` and
   `connection_id`, and loads the connection config.
7. Gateway validates the assertion signature and extracts the email/NameID.
8. Same identity lookup, tenant resolution, session steps, and `return_to`
   validation as OIDC.

### Social login buttons

OIDC and OAuth2 providers such as Discord, Google, Okta, GitHub, or Slack are
configured **per tenant** in `tenant_connections`. A tenant can therefore offer
“Sign in with Discord” or “Sign in with GitHub” to its users even if it has no
custom domain.

Because consumer domains cannot be verified, social login for consumer-domain
tenants is reached only after tenant selection. The user enters their tenant
slug, the UI shows the tenant's configured social buttons, and the OAuth2/OIDC
callback resolves the tenant from the signed state rather than from the email
domain. If no `id_mappings` entry exists, registration follows the same
`registration_enabled` + tenant self-registration rules as local flows.

## Security

- **Uniform responses:** `hrd::discover` returns the same `DiscoveryResult` shape
  for every email.
- **No config leakage:** IdP client secrets, SAML certificates, and metadata are
  never returned to the frontend.
- **Signed state:** OIDC, OAuth2, and SAML callbacks verify a signed state token
  containing `tenant_id` and `connection_id` to prevent CSRF and replay attacks.
- **Internal-only HRD:** `hrd::discover` is a Rust module; it is never reachable
  from the public internet or the browser.
- **Short-lived magic values:** state, nonce, and any intermediate cookies expire
  within minutes.
- **`return_to` validation:** redirects are validated against the tenant's
  verified domain or a configured global allow-list.
- **Rate limiting:** implement per-IP and per-email rate limiting using Redis in
  a follow-up pass.

## Implementation Phases

### Phase 1: Foundation

- Create migrations for `tenant_connections`, `tenant_local_auth`, and
  `tenant_domains`.
- Add `TenantConnectionRepo` with create/list/get-by-domain/get-by-tenant methods.
- Add `TenantLocalAuthRepo` with get-by-tenant methods.
- Add `TenantDomainRepo` with create/verify/get-by-domain methods.
- Add `ConnectionType`, `LocalAuthMethod`, and config types.
- Add global `registration_enabled` config value.
- Add domain verification token generation and DNS TXT checking.
- Unit tests for repo and types.

### Phase 2: HRD Module

- Add `crates/sso-gateway/src/hrd.rs` module with `hrd::discover`.
- Implement email parsing and verified-domain lookup.
- Return `DiscoveryResult` for known-domain connections.
- Return `DiscoveryResult::SelectTenant` for unknown or consumer domains.
- Reject `saml` connections for non-custom (consumer) domains by enforcing
  verified-domain requirement.
- Unit and integration tests covering known domain, unknown domain, consumer
  domain, missing email, and invalid email.

### Phase 3: OIDC and OAuth2 Support

- Add generic OIDC helper for fetching `/.well-known/openid-configuration`.
- Build authorization URL in HRD for `oidc` connections.
- Implement signed state cookie with `tenant_id` + `connection_id`.
- Implement `/auth/callback/oidc` handler.
- Add token exchange, ID token validation, email extraction.
- Add generic OAuth2 helper for providers without OIDC discovery.
- Build authorization URL in HRD for `oauth2` connections.
- Implement `/auth/callback/oauth2` handler.
- Add token exchange, userinfo fetch, email extraction via `userinfo_email_path`.
- Look up or create Kratos identity via admin API.
- Resolve tenant and create session.
- Validate `return_to` against verified domain or global allow-list.
- Unit and integration tests with a mock OIDC provider and a mock OAuth2
  provider.

### Phase 4: SAML Support

- Reuse existing `saml_providers` table and signing utilities.
- Build SAML `AuthnRequest` in HRD for `saml` connections on verified custom
  domains.
- Implement signed RelayState with `tenant_id` + `connection_id`.
- Implement `/auth/callback/saml` handler.
- Validate SAML response and extract NameID/email.
- Same identity/tenant/session logic and `return_to` validation as OIDC.
- Unit and integration tests with a mock SAML IdP.

### Phase 5: Per-Tenant Social Login

- Allow tenants to configure `oidc` and `oauth2` connections for social
  providers.
- Ensure the tenant is known before starting OIDC/OAuth2 (via HRD for
  custom-domain tenants or tenant-selection for consumer-domain tenants).
- Callback reuses Phase 3 logic.
- Integration tests for at least one social-style OIDC provider and one OAuth2
  provider.

### Phase 6: Local Login and Registration Polish

- Look up enabled methods from `tenant_local_auth`.
- Ensure `IdentitySelfService/CreateLoginFlow` and `SubmitLoginFlow` work with
  tenant context from tenant selection.
- Add method hints to the local login redirect so the SPA knows whether to
  render password or code UI.
- Gate identity creation in local flows by `registration_enabled` and tenant
  self-registration settings.
- Add tenant creation flow from `/login/select-tenant` when registration is
  enabled.
- Update integration tests for the full local flow, including registration.

### Phase 7: Documentation

- Update `README.md` with universal login overview.
- Add `docs/universal-login.md` covering:
  - How HRD works.
  - How to configure tenant connections.
  - How to set up OIDC and SAML IdPs.
  - Security considerations.
- Update `CHANGELOG.md` for the release.

## Testing Strategy

- **Unit tests:** new repo methods, config parsing, domain verification, HRD
  decision logic, OIDC URL building, OAuth2 URL building, SAML request building,
  state/nonce generation.
- **Integration tests:** full `hrd::discover` flows, OIDC callback with mock
  provider, OAuth2 callback with mock social provider, SAML callback with mock
  IdP, local login flow after tenant selection.
- **Coverage target:** every new source file >90% region and line coverage.
- **Regression:** run full `cargo test` and `cargo clippy` after each phase.

## Files to Touch

- `migrations/20250629210000_tenant_connections.sql`
- `migrations/20250629210001_tenant_local_auth.sql`
- `migrations/20250629210002_tenant_domains.sql`
- `crates/sso-gateway/src/db.rs` — repos + types
- `crates/sso-gateway/src/config.rs` — registration flag, global frontend
  allow-list, redirect validation
- `crates/sso-gateway/src/app.rs` — register callback routes
- `crates/sso-gateway/src/services/identity_self_service.rs` — local flow context
- `crates/sso-gateway/src/hrd.rs` — discovery logic + callback orchestration
- `crates/sso-gateway/src/oauth2.rs` — OIDC and OAuth2 callback reuse
- `crates/sso-gateway/src/saml.rs` — SAML request/response reuse
- `crates/sso-ory-client/src/kratos.rs` — admin identity lookup/creation
- `crates/sso-gateway/tests/hrd.rs` — integration tests
- `README.md`
- `docs/universal-login.md`
- `CHANGELOG.md`

## Decisions

1. **Every tenant is distinct.** There is no shared personal tenant. A tenant
   may be one person with a consumer email or a company with a custom domain.
2. **OIDC and OAuth2 providers are configured per tenant.** A tenant can add
   Discord, Google, Okta, etc. as `oidc` connections and GitHub, Slack,
   X/Twitter, etc. as `oauth2` connections. Social buttons require the tenant to
   be known first.
3. **Unknown-domain and consumer-domain emails fall back to tenant selection.**
   Only verified custom domains can be routed by HRD.
4. **Registration is gated.** New tenant creation and per-tenant self-registration
   are controlled by a global `registration_enabled` config flag.
5. **System tenant is reserved for gateway administrators.** It does not act as
   a catch-all for consumer or unknown-domain users.
6. **HRD is an internal module.** `hrd::discover` is a Rust module inside the
   gateway; it is never exposed to the browser or untrusted frontends.
7. **SAML requires a verified custom domain.** Consumer-domain tenants may use
   `password`, `code`, `oidc`, or `oauth2` connections, but never `saml`.
8. **Domain-based connections require verified domains.** `tenant_connections`
   always has a `domain`; local auth lives in `tenant_local_auth`.
9. **Callbacks identify the tenant from signed state.** OIDC, OAuth2, and SAML
   callbacks verify a signed state/RelayState token containing `tenant_id` and
   `connection_id`.
