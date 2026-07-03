# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
