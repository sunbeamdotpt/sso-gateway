---
title: Security
description: Security review findings, accepted risks, and operational recommendations for the SSO Gateway.
tags:
  - security
  - audit
  - saml
  - oauth2
  - bearer-tokens
category: reference
order: 5
nav_order: 5
---

# Security

This document summarizes the security-focused code review performed on the SSO Gateway and the controls in place.

## Authentication and authorization

- **Bearer tokens** are required for service-to-service calls. Clients send `Authorization: Bearer <token>`. The shared `auth_middleware` introspects the token via Hydra, caches active results in Postgres (`token_introspection_cache`), and resolves the tenant from the token subject using `id_mappings`.
- **Session cookies** are accepted for browser-facing flows and the federation callback handlers. The cookie (`__Host-sso_session`) is signed with HMAC-SHA256 using a key derived via HKDF-SHA256, uses the `__Host-` prefix, and is verified locally by the middleware.
- **Scopes and step-up auth** are enforced per RPC by `require_scope` and `require_amr`. The tenant, scopes, and authentication methods come from the `AuthContext` produced by introspection or cookie verification.
- **Tenant isolation** is enforced at the HTTP middleware layer for Connect-RPC calls and at the handler layer for OAuth2, SAML, SCIM, and federation protocol endpoints.
- **Public paths** (`/.well-known/`, `/oauth2/`, `/callbacks/`, `/saml/`, `/scim/v2/ServiceProviderConfig`, `/scim/v2/ResourceTypes`, `/scim/v2/Schemas`) skip shared bearer-token authentication because they perform protocol-native authentication (OAuth2 client credentials, SAML assertions, SCIM bearer tokens, OIDC/OAuth2 callback state). The branded browser self-service routes (`SELF_SERVICE_*_PATH`, defaults `/identity/…`) and the `/self-service/{recovery,verification}` email-link shims skip it as well; they carry Kratos session and CSRF cookies and Kratos performs the session checks upstream.

## Audit logging

The `audit_middleware` emits one structured log event per request to the
standard log stream, tagged with `sso_gateway::audit`. Records include the HTTP
method, path, response status, outcome, resolved tenant, authenticated actor,
`subject_type` (`user`, `agent`, or `client`), and — for delegated actions —
the acting `agent`. Audit capture is best-effort: it never blocks the response.

## Input validation and output encoding

- All SQL queries use parameterized statements. Dynamic query building in `PermissionTupleRepo::list` only injects column placeholders (`$n`), never user values.
- SAML IdP response values inserted into an auto-submit HTML form are escaped for `&`, `'`, `<`, `>`, and `"`.
- OAuth2 error responses use `axum::Json`, which performs proper JSON serialization instead of string interpolation.

## Code review fixes applied

| Issue | Fix |
|---|---|
| Federation outbound HTTP client had no request timeout. | Added a 30-second timeout to the `reqwest` client. |
| Federation callbacks were vulnerable to SSRF and DNS rebinding. | URLs must use `https://`; loopback, link-local, private ranges, and metadata hostnames are blocked. IPs are resolved through `SafeDnsResolver` and re-checked at request time. |
| TOCTOU between URL validation and outbound request. | Token/userinfo and upstream OAuth calls use the same validated `reqwest` client with the safe resolver, so validated IPs are enforced at request time. |
| SAML metadata handler and error helper used `Response::builder()...unwrap()`. | Replaced with proper error mapping and a tuple-based response builder that cannot panic. |
| SAML IdP error helper used `Response::builder()...unwrap()`. | Replaced with a tuple-based response builder. |
| SAML responses and assertions were not consistently signed. | Added `SAML_REQUIRE_SIGNED_ASSERTIONS` (default `true`) and `SAML_REQUIRE_SIGNED_RESPONSES` (default `false`). |
| SAML IdP keys were stored in plaintext. | Added optional AES-256-GCM encryption via `SAML_IDP_KEY_ENCRYPTION_KEY`. |
| SCIM HTTP helpers decoded self-encoded messages with `.expect()`. | Replaced with a fallible `decode_request` helper that returns `ServiceError::Internal`. |
| Audit log insert failures were silently dropped. | Added a `tracing::warn` on insertion failure. |
| `sqlx` default features pulled in the MySQL driver unnecessarily. | Disabled default features and explicitly enabled only Postgres, runtime, migrate, time, and macros. |
| Audit table could be truncated. | Added an append-only hash chain with an advisory lock and truncate guard. |
| Development secrets were accepted in production configs. | Added a denylist for common placeholder secrets (`change-me`, `ory`, etc.). |

## Federation and upstream identity providers

- Upstream OIDC/OAuth2 connections must use `https://`; loopback, link-local, private, and metadata addresses are rejected at resolution and again at request time to mitigate SSRF and DNS rebinding.
- OIDC callbacks validate the ID token signature (via JWKS), issuer, audience, expiry, and nonce.
- Callback `return_to` hosts are validated against `ALLOWED_RETURN_TO_HOSTS` and a public-suffix list; bare suffixes such as `com` are rejected.
- One-time `login_state` tokens are deleted after use and bound to the connection type that created them.
- Identity provisioning requires `email_verified: true` or a `trusted_provider: true` flag, unless a SAML `name_id` mapping already exists.

## Dependency advisories

- `rsa 0.9.10` is affected by [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071) (Marvin Attack timing sidechannels). No patched version is available. The crate is pulled in transitively by the SAML stack (`bergshamra`/`gamlastan`) and `sqlx-macros-core`. Risk is accepted and documented here; upgrade once a fixed `rsa` version is released.

## Accepted risks and recommendations

| Risk | Mitigation / recommendation |
|---|---|
| Introspection responses are cached in Postgres. | Cache entries are keyed by SHA-256 hash of the token and expire based on `cached_at` and the token `exp`. Revoked tokens remain usable until the cache entry expires; set `TOKEN_INTROSPECTION_CACHE_TTL_SECONDS` short enough for your revocation requirements. |
| Session cookies are verified locally. | Sessions are also stored server-side in `gateway_sessions` and can be revoked. Rotate `STATE_COOKIE_SECRET` to invalidate all existing sessions. |
| Public protocol endpoints bypass shared bearer-token auth. | Each endpoint validates tenants from protocol-specific data (`client_id`, SAML issuer/SP client, SCIM bearer token, OIDC/OAuth2 callback state); the branded self-service routes defer session checks to Kratos. Keep Ory admin endpoints network-restricted. |
| Audit logs are best-effort. | Audit records are structured log events on the standard log stream; ship logs to a durable sink and alert on ingestion gaps for the `sso_gateway::audit` target. |
| Federation relies on upstream provider security. | Only configure trusted providers, enforce `https://`, and verify tenant domains via DNS TXT records before enabling HRD. |

## Operational checklist

- [ ] Run the gateway behind a TLS-terminating load balancer.
- [ ] Restrict Ory admin endpoints to the gateway via mTLS or network policies.
- [ ] Rotate SAML signing certificates and IdP keys on a regular schedule.
- [ ] Back up Postgres and encrypt backups at rest.
- [ ] Monitor `/health/ready` and `/health/live` endpoints.
