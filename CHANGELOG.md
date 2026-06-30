# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.0.0-rc.2]: https://github.com/sunbeamdotpt/sso-gateway/releases/tag/v1.0.0-rc2
[1.0.0-rc.1]: https://github.com/sunbeamdotpt/sso-gateway/releases/tag/v1.0.0-rc1
[1.0.0-rc.0]: https://github.com/sunbeamdotpt/sso-gateway/releases/tag/v1.0.0-rc0
