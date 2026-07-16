# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project now adheres to [Calendar Versioning](https://calver.org) (CalVer).

## [2026.07.19] - 2026-07-16

### Fixed

- Leaked Hydra public URLs in self-service browser redirects. Kratos submit
  flows that return `browser_location_change_required` and Hydra login-accept
  responses that return `redirect_to` now rewrite any Hydra public URL onto the
  gateway public URL before surfacing `redirect_browser_to`. This keeps the
  browser on the gateway host so Hydra's login CSRF cookie remains valid.
  - Added `hydra_public_url` to `IdentitySelfServiceImpl` and wired it from
    `config.hydra_public_url`.
  - Added `rewrite_hydra_url` helper and applied it in
    `map_submit_response` and `accept_skippable_login`.
  - Regression tests verify that both paths rewrite Hydra URLs to gateway URLs.

## [2026.07.18] - 2026-07-16

### Added

- Cross-tenant machine-client routing via the `x-tenant-id` header.
  - `Application.cross_tenant` flag (proto, `applications` table, and
    `CreateApplicationRequest` / `UpdateApplicationRequest`) marks a service
    client as allowed to act across tenants.
  - Only the system tenant may create or update an application with
    `cross_tenant = true`, preventing privilege escalation by non-system
    tenants.
  - The shared auth middleware honors `x-tenant-id` only for authenticated
    `client` subjects whose application has `cross_tenant = true`. User and
    agent tokens remain bound to the tenant resolved by introspection.
  - Audit events log `target_tenant` and `cross_tenant = true` on override,
    and the audit middleware no longer trusts `x-tenant-id` from
    unauthenticated requests.
  - Unit and integration tests cover the gate conditions and the system-tenant
    provisioning restriction.

## [2026.07.17] - 2026-07-16

### Changed

- Documentation synced with the v2026.07.16 behavior: the API reference
  protocol table lists the branded browser self-service routes and email-link
  shims, the deployment and security guides use the correct `/health/live`
  endpoint and describe audit records as structured log events, and the README
  documents agents, the OpenFGA permission wrapper, and the branded
  self-service surface.

## [2026.07.16] - 2026-07-15

### Added

- Agent identities and on-behalf-of delegation (`iam.v1.AgentService`).
  Agents are gateway-owned non-human identities — never Kratos identities —
  backed by a managed Hydra `client_credentials` client:
  - `CreateAgent` / `GetAgent` / `ListAgents` / `UpdateAgent` / `DeleteAgent`
    / `RotateAgentSecret` manage the agent lifecycle (`agent:read` /
    `agent:admin`). The OAuth2 client secret is returned exactly once, at
    creation or rotation. Disabling an agent immediately invalidates its
    act-tokens and rejects its own client-credentials tokens.
  - `CreateAgentDelegation` / `ListAgentDelegations` /
    `RevokeAgentDelegation` implement the grant model: a user pre-authorizes
    an agent to act on their behalf with a bounded scope set until expiry.
    Only user subjects grant delegations, and the delegating user (or an
    `agent:admin` caller) revokes.
  - `MintAgentActToken` lets the agent mint a short-lived opaque act-token
    (`sat_…`) against a live delegation (requires `agent:act`). Act-tokens
    never outlive their delegation.
  - `IntrospectAgentActToken` returns RFC 7662-shaped claims (`sub` = user,
    `act` = agent) to any authenticated caller in the token's tenant;
    cross-tenant tokens introspect as inactive.
  - Act-tokens are opaque and re-validated on every use. Resolutions are
    cached in-process (moka) with invalidate-on-write: revocation or agent
    disable evicts locally and broadcasts over core NATS pub/sub
    (`NATS_URL`) so other replicas evict too. A seconds-long TTL
    (`AGENT_CACHE_TTL_SECONDS`, default 5) is only a backstop for missed
    broadcasts; without NATS the gateway degrades to single-instance
    semantics. Act-token lifetime is bounded by
    `AGENT_ACT_TOKEN_TTL_SECONDS` (default 3600).
  - The shared auth middleware resolves act-tokens before Hydra
    introspection, classifies every subject as `user`, `agent` (registered
    agent client), or `client` (plain machine client), and records
    `subject_type` and `agent` on audit events. A disabled agent's own
    client-credentials tokens are rejected at authentication.
  - `agents`, `agent_delegations`, and `agent_act_tokens` tables (cascading
    deletes; act-tokens stored as hashes only).
- Branded browser self-service surface. Every Kratos URL that can reach a
  browser (flow init redirects, AAL2 upgrades, logout chains, email token
  links, OIDC callbacks, the WebAuthn script) is rewritten onto gateway-owned
  paths, so no upstream construct leaks into an address bar, redirect chain,
  or inbox:
  - The gateway proxies the browser routes at nine independently configurable
    paths (`SELF_SERVICE_LOGIN_PATH`, `SELF_SERVICE_REGISTRATION_PATH`,
    `SELF_SERVICE_SETTINGS_PATH`, `SELF_SERVICE_RECOVERY_PATH`,
    `SELF_SERVICE_VERIFICATION_PATH`, `SELF_SERVICE_LOGOUT_PATH`,
    `SELF_SERVICE_ERRORS_PATH`, `SELF_SERVICE_OIDC_CALLBACK_PATH`,
    `SELF_SERVICE_WEBAUTHN_JS_PATH`; defaults under `/identity/…`). Token-
    bearing links dispatch to the Kratos token-submission routes; redirect
    (`Location`) responses are rewritten onto the branded surface, including
    URLs nested in `return_to` / `redirect_uri` parameters.
  - Branded routes skip bearer-token authentication (they carry Kratos session
    and CSRF cookies) and are proxied with method, query, body, and cookies
    preserved, including repeated `Set-Cookie` headers.
  - With Kratos `serve.public.base_url` pointed at the gateway, recovery and
    verification email links land on `/self-service/{recovery,verification}`
    shims that bounce the browser to the branded path (302) without consuming
    the token.
  - `deploy/kratos.yml` points Kratos' public base URL at the gateway and
    renames the session cookie to `sunbeam_session`
    (`session.cookie.name`).

### Changed

- The WebAuthn JavaScript bundle is now served at the branded
  `SELF_SERVICE_WEBAUTHN_JS_PATH` (default `/identity/webauthn.js`) instead of
  `/.well-known/ory/webauthn.js`.

### Fixed

- `CreateLoginFlow` with a `login_challenge` no longer strands the browser on
  Kratos' `session_already_available` error when the caller already has a
  Kratos session and Hydra's login request has `skip` set. Kratos accepts the
  login server-side on that path but drops Hydra's `redirect_to` for JSON
  clients, which trapped login UIs in a logout-and-retry loop. The gateway now
  mirrors Kratos' browser behavior: it fetches the Hydra login request first,
  and when `skip` is set and the caller's Kratos session is valid, it accepts
  the login request with the session's subject (plus its AMR and session id)
  and returns Hydra's `redirect_to` as `redirect_browser_to`. When `skip` is
  unset, the session is missing, or the login request cannot be fetched, flow
  creation proceeds through Kratos exactly as before.
- Self-service submits that end in Kratos' `browser_location_change_required`
  (AAL2 upgrades, post-login bounces) returned the Kratos-hosted URL verbatim
  in `redirect_browser_to`, leaking the upstream endpoint and path shape to
  browsers. The location is now rewritten onto the branded surface and its raw
  Kratos flow id is scrubbed, matching every other gateway-facing URL.
  Recovery and verification token exchange responses
  (`SubmitRecoveryTokenResponse.redirect_to`,
  `SubmitVerificationTokenResponse.redirect_to`) and `LogoutFlow.logout_url`
  are branded the same way.

## [2026.07.15] - 2026-07-15

### Added

- Tenant namespace lifecycle on `PermissionService`. Third-party services can
  now register their own permission namespaces with full OpenFGA authorization
  models instead of relying on the internal SCIM-only provisioning path:
  - `EnsurePermissionNamespace` registers a namespace with an arbitrary rich
    model (`schema_version`, `type_definitions`, `conditions` as
    `google.protobuf.Struct`). Re-ensuring the identical model is a no-op; a
    changed model publishes a new OpenFGA model version into the existing
    store, so relation tuples are never re-initialized. Object types are
    indexed per tenant so tuple and check calls resolve a type
    (`KanbanProject`) to its owning namespace store; a type may be claimed by
    only one namespace per tenant.
  - `GetPermissionNamespace` / `ListPermissionNamespaces` read back the
    registered model and its type list.
  - `DeletePermissionNamespace` tears down the OpenFGA store, the mirrored
    tuples, and the registration.
  - `WriteRelationTuples` batches creates and deletes (up to 100 keys per
    direction), with optional OpenFGA conditions and condition context per
    key.
  - `ListUsers` lists the subjects that have a relation on an object
    (OpenFGA backend only).
  - `CheckPermission`, `ExpandPermissions`, `ExpandObjects`, and `ListUsers`
    accept optional `context`, `contextual_tuples`, and `consistency`
    (`minimize_latency` / `higher_consistency`) which pass through to OpenFGA
    verbatim; the Keto backend rejects them with a configuration error.
  - `ListRelationTuples` is now keyset-paginated (default 50, max 200) over
    the mirrored tuples.
- `permission_namespaces` and `permission_namespace_types` tables persist the
  tenant namespace registry (replacing the in-memory placeholder), plus a
  keyset index on `permission_tuples`.

## [2026.07.14] - 2026-07-15

### Added

- Device verification for the OAuth 2.0 Device Authorization Grant (RFC 8628).
  Two new `OAuth2DeviceService` RPCs cover the user side of the flow:
  `GetDeviceVerification` exchanges the device-displayed user code for an
  opaque gateway challenge (relaying Hydra's device CSRF cookie to the
  caller), and `AcceptDeviceVerification` approves the code and returns the
  URL the browser must follow, with the embedded client id scrubbed back to
  the gateway's public ULID. A browser-facing `GET /oauth2/device/verify`
  proxy route forwards the post-accept verifier leg to Hydra, translating the
  public client id and reassembling split `Cookie` header fields so Hydra's
  device CSRF check passes.

### Fixed

- `OAuth2DeviceService.GetDeviceToken` polled `/oauth2/device/token`, a route
  that does not exist in Hydra — every poll returned 404. RFC 8628 §3.4
  polls the standard token endpoint with the
  `urn:ietf:params:oauth:grant-type:device_code` grant; the RPC now posts to
  `/oauth2/token`.

### Changed

- Updated `sunbeam-g2v` from 0.3.3 to 0.5.2. The framework's `jwt` and `keto`
  features were removed upstream (the gateway used neither), and the `auth`
  feature is now enabled — 0.5.2 fails to compile without it because
  `AuthConfig::validate` references the optional `ulid` dependency
  unconditionally. `jsonwebtoken` now pins the `aws_lc_rs` crypto provider
  explicitly; g2v's removed `jwt` feature previously supplied a provider
  through feature unification, and without one the OIDC callback panics at
  runtime.

## [2026.07.13] - 2026-07-14

### Added

- `SelfServiceFlow.redirect_browser_to` (field 14) carries the browser
  redirect target when a self-service submit completes with Kratos'
  `browser_location_change_required` outcome (e.g. a login-challenge flow
  that must bounce the browser back to the authorize URL). Clients no longer
  need to scrape the target out of an error string.

### Fixed

- A successful login or registration submit on a flow created with a
  `login_challenge` is answered by Kratos with 422
  `browser_location_change_required`, and the `Set-Cookie:
  ory_kratos_session` rides on that 422 response. The Kratos client treated
  every non-2xx as an error and discarded the headers, so the session cookie
  never reached the browser — downstream consumers (consent, token claims,
  mail login) then saw an anonymous session. The client now surfaces the 422
  as a redirect carrying the location and the cookie headers, and all five
  submit RPCs (`Submit{Login,Registration,Settings,Recovery,Verification}Flow`)
  return `redirect_browser_to` and attach the captured cookies to the
  response.

## [2026.07.12] - 2026-07-14

### Fixed

- HTTP/2 clients may split cookies across multiple `Cookie` header fields
  (RFC 7540 §8.1.2.5), but two request paths read only the first field. The
  `/oauth2/auth` proxy now reassembles all fields with `"; "` before
  forwarding to Hydra — previously a CSRF cookie landing in a later field was
  silently dropped, reproducing "No CSRF value available in the session
  cookie" on Chromium-based browsers. The auth middleware's
  `session_cookie()` got the same treatment; a split gateway session cookie
  no longer fails authentication.

## [2026.07.11] - 2026-07-14

### Fixed

- `GetConsentRequest`, `AcceptConsent`, `RejectConsent`, and the logout trio
  (`GetLogoutRequest` / `AcceptLogout` / `RejectLogout`) no longer fail with
  `not_found: mapping not found` when handed Hydra's raw challenge. Hydra's
  post-login redirect delivers the raw `consent_challenge` (and the logout
  redirect the raw `logout_challenge`) to the consent/logout app, so on a
  mapping lookup miss the value is passed through unchanged — Hydra still
  validates the challenge cryptographically. This mirrors the existing
  `login_challenge` passthrough; logout passthrough resolves the tenant from
  the caller's request context.

## [2026.07.10] - 2026-07-14

### Fixed

- The `/oauth2/auth` proxy forwarded Hydra's `Set-Cookie` headers to the
  browser but dropped the browser's `Cookie` header on the way back to Hydra,
  so Hydra's CSRF check never saw `oauth2_authentication_csrf` and rejected
  every post-login and post-consent authorize with `request_forbidden: No CSRF
  value available in the session cookie`. The handler now forwards the
  incoming `Cookie` header verbatim, and `HydraClient::authorize` accepts an
  optional cookie to send upstream. This is the request-direction mirror of
  the 2026.07.7/2026.07.8 `Set-Cookie` fixes.

## [2026.07.9] - 2026-07-14

### Fixed

- Recovery and verification token submissions (`SubmitRecoveryToken` /
  `SubmitVerificationToken`) no longer leak raw Kratos flow UUIDs: the `flow`
  query parameter in Kratos' redirect location is replaced with an opaque
  gateway-minted ULID that round-trips through `GetSettingsFlow`. The same
  scrubbing now applies to Kratos-owned URLs inside self-service flow payloads
  (`request_url`, `ui.action`, and UI-node anchor/image/script/input URLs),
  while caller- and application-owned URLs (`return_to`, OAuth2 client URIs)
  remain host-rewrite-only.

## [2026.07.8] - 2026-07-10

### Changed

- The identity model is now gateway-owned. Kratos persists only the minimal base
  identity (`{email}` plus credentials) under the base schema id set via
  `KRATOS_DEFAULT_SCHEMA_ID` (dev `default`, prod `employee`). The gateway owns
  the full trait set, the per-tenant schema binding, and tenant membership
  (`tenant_memberships`). Reads assemble the caller-facing identity from
  membership; writes validate against the tenant's versioned schema and persist
  only the base email to Kratos. Email is normalized (lowercase + trim) and is
  immutable. A single base identity may belong to many tenants, and superset
  schemas may add traits and enable extra methods (SAML/SCIM/OIDC) that Kratos
  never sees. Federation, SCIM, self-service, and settings flows all route
  through this model.
- Identity schemas are now versioned (`tenant_identity_schemas.version`).

### Fixed

- The public self-service proxy copied upstream response headers with
  `HeaderMap::insert`, which overwrites earlier values for the same name and
  dropped all but the last `Set-Cookie`. It now appends every value so repeated
  headers — notably multiple Kratos cookies — reach the browser. This is the
  same defect class as the 2026.07.7 `/oauth2/auth` CSRF-cookie drop.

### Tests

- Added a divergent end-to-end test against a real Kratos v25.4 proving Kratos
  holds only the base `{email}` while the gateway owns the full traits and
  schema binding. Bumped the Kratos test image from v1.3.0 to v25.4.0 to match
  production.

## [2026.07.7] - 2026-07-10

### Added

- `KRATOS_DEFAULT_SCHEMA_ID` and the minimal base identity schema, laying the
  groundwork for gateway-owned traits.

### Fixed

- The `/oauth2/auth` proxy now forwards Hydra's `Set-Cookie` headers (notably
  `oauth2_authentication_csrf`) on its redirect, so the post-login authorize no
  longer fails with "No CSRF value available in the session cookie."

### Documentation

- Captured the phase-2 multi-tenant membership design.

## [2026.07.6] - 2026-07-10

### Fixed

- Reverted the raw Kratos flow id passthrough added in 2026.07.5 for
  `GetLoginFlow` / `SubmitLoginFlow`. Accepting an unminted Kratos flow id made
  Ory's internal identifier a valid gateway input — a backend fingerprint that
  the gateway's opaqueness contract forbids. An unknown flow id now correctly
  returns `not_found`; the login UI re-initializes the flow on that response
  (see sso-ui). The `login_challenge` passthrough from 2026.07.4 is unchanged —
  that value is part of the OIDC spec and is not an Ory-internal identifier.
- The self-service UI mapper now also collapses an `identifier` input node whose
  value Kratos delivers as a *string* encoding of a same-email array
  (`"[\"alice@example.com\",\"alice@example.com\"]"`). The 2026.07.5 collapse
  only matched a real JSON array (`value.as_array()`), so the string-encoded
  form slipped through, rendered as the literal `[...]` text, and — because a
  failed submit re-renders the form with the same value — grew by one copy on
  every attempt. Collapsing to a scalar on every render breaks the cycle.
  Genuinely multi-valued arrays are still left unchanged.

## [2026.07.5] - 2026-07-10

### Fixed

- `GetLoginFlow` and `SubmitLoginFlow` now forward Kratos's raw flow id to
  Kratos when no gateway-minted public token exists. The standard Ory browser
  flow can hand the raw flow id straight to the login UI (a Kratos-initiated
  redirect, or a flow that pre-dates the ULID migration), in which case there
  is no mapping to resolve. The gateway previously returned `not_found`,
  trapping the browser in a redirect loop. Kratos issued and cryptographically
  validates the flow id, and the browser already holds it in the URL, so
  passthrough is safe and leaks nothing.
- The self-service UI mapper now collapses an `identifier` input node whose
  value Kratos prefilled as a JSON array of the same email (e.g.
  `["alice@example.com","alice@example.com"]`) down to the single email. The
  generic coercion previously rendered the array as the literal text
  `[...]`, which the browser submitted verbatim; no identity matched it, so
  the password check rejected and the login looped. Genuinely multi-valued
  arrays are left unchanged.

## [2026.07.4] - 2026-07-09

### Fixed

- `CreateLoginFlow` and `CreateRegistrationFlow` (both `IdentitySelfService` and
  the legacy `Identity` service) now forward Hydra's raw login challenge to
  Kratos when no gateway-minted mapping exists. Previously these RPCs returned
  `not_found` for the standard Ory login flow, where Hydra delivers the raw
  challenge to the login UI via the redirect query string, trapping the browser
  in a redirect loop. Kratos cryptographically validates the challenge either
  way, so passthrough is safe.

## [2026.07.3] - 2026-07-09

### Added

- `/oauth2/register` endpoint for dynamic OAuth2 client registration, protected by
  `application:admin` and backed by Hydra with gateway-level ID mapping.
- `/userinfo` public endpoint alias in addition to `/oauth2/userinfo`.

### Changed

- `CreateApplication` and `/oauth2/register` now accept `http://` redirect URIs
  when the host is a loopback address (`localhost`, `127.0.0.1`, or `[::1]`)
  without requiring the `allow_http_redirect_uris` configuration flag.
- `CreateApplication`, `CreateClientCredential`, and `/oauth2/register` now set
  the Hydra `client_id` to the gateway public ULID so internal Hydra identifiers
  never appear in OAuth2 protocol artifacts such as `id_token` `aud` claims.

### Fixed

- `identity_self_service_consent_service` integration test now seeds and uses
  opaque public tokens for Kratos flow, recovery/verification token, error, and
  Hydra consent/logout challenge identifiers.
- `oauth2_service` integration test binds the gateway port before starting Hydra
  so Hydra's self-issuer redirects remain on the gateway origin.
- OIDC conformance test now uses an opaque ULID subject in the `id_token` and
  `userinfo` sub claim.

## [2026.07.2] - 2026-07-09

Superseded by `2026.07.3`; no artifacts were published for this version.

## [2026.07.1] - 2026-07-08

### Added

- Optional OpenFGA permission backend, gated by the `openfga` Cargo feature (enabled
  by default). When both `openfga` and `keto` are compiled, OpenFGA is preferred.
- New internal `sso-openfga-client` crate for OpenFGA store, model, and tuple
  management.
- Tenant-owned OpenFGA stores and authorization models via `NamespaceMappingRepo`;
  objects are not tenant-prefixed. Keto continues to use the existing
  `{tenant_id}:{object}` prefix.
- `PermissionBackend` trait abstracting `check_permission`, `create_relation_tuple`,
  `delete_relation_tuple`, `expand`, `expand_objects`, and `ensure_namespace`.
- Integration test parity for OpenFGA:
  `tests/permission_service_openfga.rs` and `tests/scim_service_openfga.rs`.

### Changed

- `PermissionServiceImpl` and `ScimServiceImpl` now operate over `Arc<dyn PermissionBackend>`.
- `permissions_backend` config selects the active backend at runtime.
- The system bootstrap OAuth2 client now receives full administrative scopes for
  every gateway service:
  `tenant:read tenant:admin identity:read identity:admin application:read application:admin
   scim:read scim:admin permission:read permission:admin`.

### Fixed

- Feature-gated the OpenFGA URL validation test so `cargo test` passes when the
  crate is built with only the `keto` feature.

## [1.0.0-rc.15] - 2026-07-08

### Added

- `ClientCredentialService` Connect-RPC service and protobuf messages
  (`ClientCredential`, `ClientCredentialSecret`, `CreateClientCredentialRequest`,
  `GetClientCredentialRequest`, `ListClientCredentialsRequest`,
  `UpdateClientCredentialRequest`, `DeleteClientCredentialRequest`,
  `RotateClientCredentialSecretRequest`). This provides lifecycle management for
  machine-to-machine OAuth2 clients (`client_credentials` grant), protected by
  `application:read` / `application:admin`.

### Fixed

- The system bootstrap OAuth2 client is now created with scopes
  `tenant:read tenant:admin application:admin` and, on startup, existing mapped
  bootstrap clients are updated to match if their scopes differ. This fixes
  `ListTenants` returning `PermissionDenied` when the bootstrap token did not
  carry `tenant:read` / `tenant:admin`.

## [1.0.0-rc.14] - 2026-07-07

### Added

- `PermissionService.ExpandObjects` RPC and protobuf messages
  (`ExpandObjectsRequest`, `ExpandObjectsResponse`). This queries Keto for all
  objects a subject (or subject set) has a given relation on, returning the
  gateway-level object identifiers with the tenant prefix stripped.

### Fixed

- Hardened `sso-ory-client` integration test container startup against
  RootlessKit ephemeral-port races and IPv6 connection failures by retrying
  startup, cleaning up leaked testcontainers, and binding to `127.0.0.1`
  explicitly.

## [1.0.0-rc.13] - 2026-07-06

### Added

- `tenant_id` is now included in the gateway's `/oauth2/introspect` response.
  The tenant is resolved from the token subject using gateway `id_mappings`,
  querying both the `hydra` and `kratos` backends so the field is present for
  client-credentials tokens and user tokens alike.

### Changed

- `resolve_tenant_from_subject` now queries `hydra` first and falls back to
  `kratos` before treating a subject as unknown. This makes bearer-token
  authentication work for user access tokens whose subject is a Kratos identity
  ID, not just client-credentials tokens whose subject is a Hydra client ID.

### Fixed

- `/oauth2/introspect` now fails introspection (`{"active": false}`) when
  Hydra reports an active token but the gateway has no tenant mapping for its
  subject. Every bearer token consumed by the gateway must be attributable to a
  tenant.

## [1.0.0-rc.12] - 2026-07-04

### Changed

- Magic-link URLs returned by `IdentityService.CreateRecoveryLink` and
  `IdentityService.GetVerificationMessage` now include a `flow` query parameter
  (`/recovery?flow=...&token=...` and `/verification?flow=...&token=...`). The
  `flow` value is extracted from the upstream Kratos link so the UI can pass it
  to `IdentitySelfService.SubmitRecoveryToken` / `SubmitVerificationToken`.
- `IdentitySelfService.SubmitRecoveryToken` and
  `IdentitySelfService.SubmitVerificationToken` now require a `flow` field and
  send it to Kratos as a query parameter. This matches Kratos v25.4.0, which
  rejects token-only validation in the JSON-facing code path with
  "The flow query parameter is missing or malformed."

### Added

- `flow` field to `RecoveryLink`, `VerificationMessage`,
  `SubmitRecoveryTokenRequest`, and `SubmitVerificationTokenRequest` protobuf
  messages.
- Unit and integration regression coverage for the `flow` parameter exchange.

## [1.0.0-rc.11] - 2026-07-04

### Changed

- Magic-link URLs returned by `IdentityService.CreateRecoveryLink` and
  `IdentityService.GetVerificationMessage` now point to `UI_PUBLIC_URL`
  (`/recovery?token=...` and `/verification?token=...`) instead of being
  proxied through `/self-service/{*path}`. `UI_PUBLIC_URL` defaults to
  `PUBLIC_BASE_URL` when unset.
- The general `/self-service/{*path}` HTTP proxy has been removed. Browser
  self-service flows now go exclusively through `IdentitySelfService`
  Connect-RPC methods.

### Added

- `IdentitySelfService.SubmitRecoveryToken` and
  `IdentitySelfService.SubmitVerificationToken` let the UI exchange Kratos
  magic-link tokens. They return the upstream `redirect_to` URL and propagate
  `Set-Cookie` headers (including session and CSRF cookies) through Connect-RPC
  response metadata.
- Gateway configuration field `UI_PUBLIC_URL` for UI-facing magic-link URLs.
- Unit and integration regression coverage for the new magic-link flow.

## [1.0.0-rc.10] - 2026-07-04

### Fixed

- `IdentityService.CreateRecoveryLink` now parses the recovery token from the
  `token` query parameter of `recovery_link` when Kratos omits the
  `recovery_token` field (Kratos v25.4.0 behaviour).
- Public self-service proxy no longer follows upstream Kratos redirects, which
  previously caused `502 upstream self-service request failed` when Kratos
  redirected to an unreachable internal URL.

### Added

- Regression tests for both fixes above.

## [1.0.0-rc.9] - 2026-07-03

### Added

- `IdentitySelfService.GetTenantCapabilities` lets the UI detect whether OAuth2
  consent is enabled for a tenant, removing the need for Hydra env vars in the
  frontend.
- `IdentityService.CreateRecoveryLink` and `IdentityService.GetVerificationMessage`
  provide scope-protected (`identity:admin`) alternatives to Kratos admin
  endpoints for integration testing and support flows.
- Public self-service HTTP proxy routes (`/self-service/{*path}` and
  `/.well-known/ory/webauthn.js`) that rewrite Kratos URLs to gateway URLs in
  JSON, HTML, and redirect responses.

### Changed

- Audit logs are now emitted as structured logs to the standard log stream with
  target `sso_gateway::audit` instead of being written to the `audit_log` table.
  The `PgAuditLogStore`, `AuditLogStore` trait, and gateway wiring have been
  removed.

### Documentation

- Documented the self-service error-shape contract in `docs/self-service-api.md`.
- Updated `AGENTS.md` and `docs/architecture.md` to reflect structured-log audit
  records.

## [1.0.0-rc.8] - 2026-07-03

### Fixed

- Corrected `HydraClient::introspect_token` to call `/admin/oauth2/introspect`
  on Hydra's admin port. Previously it used `/oauth2/introspect`, which Hydra
  v2.2.0 redirects from, causing token introspection to fail in containerized
  deployments.

### Added

- Regression test `introspect_token_uses_admin_path` to lock in the correct
  Hydra admin introspection path.

## [1.0.0-rc.7] - 2026-07-03

### Added

- Federation callback support for upstream OAuth2/OIDC identity providers.
  - New `FederationCallback` and tenant connection domain messages in the
    Connect-RPC API.
  - HRD domain verification to route users to the correct upstream provider.
  - Identity provisioning from upstream OIDC claims into tenant-local
    identities.
- Encrypted key storage, replay cache, and login-state tables in the metadata
  store.
- Cached token introspection backed by the metadata store to reduce Hydra
  round-trips.
- Session cookie authentication in the gateway middleware for browser-facing
  flows.
- `cargo audit` CI workflow.

### Changed

- Hardened OIDC, SAML, session, network, and API boundaries across the service
  layer and HTTP handlers.
- Moved HTTP handlers into `services/handlers` and hardened SAML/OAuth2
  endpoints.
- Refreshed migration timestamps and consolidated session/login-state/replay-cache
  schemas.
- Updated workspace dependencies and container configuration for the security
  review.
- Removed obsolete `TenantApiKey` module.

### Fixed

- Fixed TOCTOU and SSRF vulnerabilities in outbound request handling.

### Security

- Continued ignoring `RUSTSEC-2023-0071` (rsa Marvin Attack) pending an upstream
  fix.

## [1.0.0-rc.6] - 2026-07-01

### Added

- OAuth 2.0 Device Authorization Grant support.
  - New public HTTP proxy route `/oauth2/device/{*path}` forwards device
    authorization and token requests to Ory Hydra.
  - OIDC discovery document now advertises `device_authorization_endpoint` and
    the `urn:ietf:params:oauth:grant-type:device_code` grant type.
  - New `OAuth2DeviceService` Connect-RPC API with `AuthorizeDevice` and
    `GetDeviceToken` methods.

### Fixed

- Propagate `Set-Cookie` headers from Ory Kratos through the gateway on
  self-service browser flow creation, get, and submission. The UI already
  forwards these cookies; the gateway now emits them in Connect-RPC response
  metadata so the browser agent can send them back on subsequent requests.

## [1.0.0-rc.5] - 2026-07-01

### Fixed

- Health check endpoints (`/health/*`) are no longer auth-gated.

## [1.0.0-rc.4] - 2026-07-01

## [1.0.0-rc.3] - 2026-07-01

### Added

- Extended `CreateLoginFlowRequest` and `CreateRegistrationFlowRequest` with
  query parameters needed by the browser UI:
  `aal`, `refresh`, `organization`, `via`, `login_challenge`, and `identity_schema`.
- Added `BrowserIdentity`, `VerifiableAddress`, and `RecoveryAddress` messages;
  `BrowserSession` now exposes the full identity object alongside the existing
  flattened `identity_traits`.
- Added `OAuth2Client` message and embedded it in `ConsentRequest` and
  `LogoutRequest`, exposing `skip_consent` and `skip_logout_consent`.
- Enriched the typed self-service flow model (`SelfServiceFlow`, `UiNode` input/
  text/anchor/image/script attributes, `UiNodeMeta`, `UiMessage`) so the browser
  client can translate it for `@ory/elements-markup` while keeping the gateway
  contract vendor-agnostic.

### Changed

- `KratosClient` browser and API flow creation methods now accept a query
  parameter slice instead of only `return_to`.

## [1.0.0-rc.2] - 2026-06-30

### Added

- Conformance test harness for OAuth 2.0, OpenID Connect, and SAML 2.0.
  - Exercises public protocol endpoints against the full gateway stack and
    backing testcontainers.
  - Covers discovery, token, introspection, revocation, authorization-code flow,
    `id_token` validation, userinfo, SAML SP metadata, and SAML SSO response
    generation.

### Fixed

- Added `token_endpoint_auth_methods_supported` to the OIDC discovery document.
- Corrected the Hydra userinfo proxy path from `/oauth2/userinfo` to `/userinfo`.

## [1.0.0-rc.1] - 2026-06-29

### Added

- `IdentitySelfService` Connect-RPC API for browser-facing Kratos self-service flows.
  - Session introspection (`ToSession`), flow get/submit for login, registration,
    settings, recovery, and verification.
  - Browser flow creation for login, registration, settings, recovery, verification,
    and logout.
  - Flow error and WebAuthn JS helpers.
- `OAuth2ConsentService` Connect-RPC API for Hydra consent and logout requests.
- Cookie-based session authentication in the gateway middleware.
- Hydra-compatible REST logout request handlers (`/oauth2/auth/requests/logout`).

### Changed

- Renamed `SelfServiceService` to `IdentitySelfService` for clearer API naming.

## [1.0.0-rc.0] - 2026-06-29

### Added

- Initial release of the SSO Gateway.
- Unified IAM facade over Ory Hydra, Kratos, and Keto via Connect-RPC.
- Identity, application, permission, federation, SCIM 2.0, and tenant services.
- SAML 2.0 Service Provider and Identity Provider support.
- Asynchronous audit logging to Postgres.
- Multi-tenant JSON schema validation for identities.
- Full unit and integration test suite with >90% library coverage.
- Multi-architecture container image (`linux/amd64`, `linux/arm64`).
- GitHub Actions release workflow for GHCR.
- Security documentation and deployment guides.

### Security

- Removed OpenSSL from the release build; TLS is provided by `rustls`/`aws-lc`.
- Replaced production `unwrap()`/`expect()` paths in SAML and SCIM modules.
- Added request timeout to federation outbound HTTP client.
- Hardened HTML escape routine to also escape single quotes.
- Added warning logging for failed audit-log inserts.

### Known Issues

- `rsa 0.9.x` is affected by `RUSTSEC-2023-0071` (Marvin Attack). No patched
  version is available upstream; risk is documented in `docs/security.md`.

[2026.07.2]: https://github.com/sunbeamdotpt/sso-gateway/releases/tag/v2026.07.2
[2026.07.1]: https://github.com/sunbeamdotpt/sso-gateway/releases/tag/v2026.07.1
[1.0.0-rc.15]: https://github.com/sunbeamdotpt/sso-gateway/releases/tag/v1.0.0-rc.15
[1.0.0-rc.11]: https://github.com/sunbeamdotpt/sso-gateway/releases/tag/v1.0.0-rc11
[1.0.0-rc.10]: https://github.com/sunbeamdotpt/sso-gateway/releases/tag/v1.0.0-rc10
[1.0.0-rc.9]: https://github.com/sunbeamdotpt/sso-gateway/releases/tag/v1.0.0-rc9
[1.0.0-rc.8]: https://github.com/sunbeamdotpt/sso-gateway/releases/tag/v1.0.0-rc8
[1.0.0-rc.7]: https://github.com/sunbeamdotpt/sso-gateway/releases/tag/v1.0.0-rc7
[1.0.0-rc.6]: https://github.com/sunbeamdotpt/sso-gateway/releases/tag/v1.0.0-rc6
[1.0.0-rc.5]: https://github.com/sunbeamdotpt/sso-gateway/releases/tag/v1.0.0-rc5
[1.0.0-rc.4]: https://github.com/sunbeamdotpt/sso-gateway/releases/tag/v1.0.0-rc4
[1.0.0-rc.3]: https://github.com/sunbeamdotpt/sso-gateway/releases/tag/v1.0.0-rc3
[1.0.0-rc.2]: https://github.com/sunbeamdotpt/sso-gateway/releases/tag/v1.0.0-rc2
[1.0.0-rc.1]: https://github.com/sunbeamdotpt/sso-gateway/releases/tag/v1.0.0-rc1
[1.0.0-rc.0]: https://github.com/sunbeamdotpt/sso-gateway/releases/tag/v1.0.0-rc0
