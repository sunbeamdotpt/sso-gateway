# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project now adheres to [Calendar Versioning](https://calver.org) (CalVer).

## [Unreleased]

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
