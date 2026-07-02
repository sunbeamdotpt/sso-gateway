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

- **Bearer tokens** are required for all protected endpoints. Clients send `Authorization: Bearer <token>`. The shared `auth_middleware` introspects the token via Hydra, caches the result in Postgres (`token_introspection_cache`), and resolves the tenant from the token subject using `id_mappings`.
- **Scopes** are enforced per RPC by `require_scope`. The tenant and scopes come from the `AuthContext` produced by introspection.
- **Tenant isolation** is enforced at the HTTP middleware layer for Connect-RPC calls and at the handler layer for OAuth2, SAML, and SCIM protocol endpoints.
- **Public paths** (`/.well-known/`, `/oauth2/`, `/saml/`, `/scim/v2/ServiceProviderConfig`, `/scim/v2/ResourceTypes`, `/scim/v2/Schemas`) skip shared bearer-token authentication because they perform protocol-native authentication (OAuth2 client credentials, SAML assertions, SCIM bearer tokens).

## Audit logging

The `audit_middleware` records method, path, resolved tenant, authenticated actor, and outcome asynchronously. Failures to write audit rows are logged with `tracing::warn` but do not block the response.

## Input validation and output encoding

- All SQL queries use parameterized statements. Dynamic query building in `PermissionTupleRepo::list` only injects column placeholders (`$n`), never user values.
- SAML IdP response values inserted into an auto-submit HTML form are escaped for `&`, `'`, `<`, `>`, and `"`.
- OAuth2 error responses use `axum::Json`, which performs proper JSON serialization instead of string interpolation.

## Code review fixes applied

| Issue | Fix |
|---|---|
| Federation outbound HTTP client had no request timeout. | Added a 30-second timeout to the `reqwest` client. |
| SAML metadata handler and error helper used `Response::builder()...unwrap()`. | Replaced with proper error mapping and a tuple-based response builder that cannot panic. |
| SAML IdP error helper used `Response::builder()...unwrap()`. | Replaced with a tuple-based response builder. |
| SCIM HTTP helpers decoded self-encoded messages with `.expect()`. | Replaced with a fallible `decode_request` helper that returns `ServiceError::Internal`. |
| Audit log insert failures were silently dropped. | Added a `tracing::warn` on insertion failure. |
| `sqlx` default features pulled in the MySQL driver unnecessarily. | Disabled default features and explicitly enabled only Postgres, runtime, migrate, time, and macros. |

## Dependency advisories

- `rsa 0.9.10` is affected by [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071) (Marvin Attack timing sidechannels). No patched version is available. The crate is pulled in transitively by the SAML stack (`bergshamra`/`gamlastan`) and `sqlx-macros-core`. Risk is accepted and documented here; upgrade once a fixed `rsa` version is released.

## Accepted risks and recommendations

| Risk | Mitigation / recommendation |
|---|---|
| Introspection responses are cached in Postgres. | Cache entries are keyed by SHA-256 hash of the token and expire based on `cached_at` and the token `exp`. Revoked tokens remain usable until the cache entry expires; set `max_age` short enough for your revocation requirements. |
| Public protocol endpoints bypass shared bearer-token auth. | Each endpoint validates tenants from protocol-specific data (`client_id`, SAML issuer/SP client, SCIM bearer token). Keep Ory admin endpoints network-restricted. |
| Audit logs are best-effort. | Monitor `audit log insertion failed` warnings and alert if audit writes fail repeatedly. |

## Operational checklist

- [ ] Run the gateway behind a TLS-terminating load balancer.
- [ ] Restrict Ory admin endpoints to the gateway via mTLS or network policies.
- [ ] Rotate SAML signing certificates and IdP keys on a regular schedule.
- [ ] Back up Postgres and encrypt backups at rest.
- [ ] Monitor `/health/ready` and `/health/alive` endpoints.
