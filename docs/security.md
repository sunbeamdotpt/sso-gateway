---
title: Security
description: Security review findings, accepted risks, and operational recommendations for the SSO Gateway.
tags:
  - security
  - audit
  - saml
  - api-keys
category: reference
order: 5
nav_order: 5
---

# Security

This document summarizes the security-focused code review performed on the SSO Gateway and the controls in place.

## Authentication and authorization

- **API keys** are hashed with SHA-256 and looked up by hash in `tenant_api_keys`. Each key has an optional expiration time; expired keys are rejected at lookup time.
- **Scopes** are enforced per RPC by `require_scope`. Requests that only provide `X-Tenant-Id` (for example, the initial bootstrap flow) bypass scope checks.
- **Tenant isolation** is enforced at the HTTP middleware layer for Connect-RPC calls and at the handler layer for OAuth2, SAML, and SCIM protocol endpoints.
- **Public paths** (`/.well-known/`, `/oauth2/`, `/saml/`, `/scim/`) skip API-key authentication because they validate the tenant from protocol-specific parameters.

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
| API key hashes are unsalted. | This is acceptable for the current threat model because keys are random and high-entropy. If the key table is ever exposed, consider migrating to per-key salted hashes. |
| Database lookup of API key hashes may leak timing information. | Invalid and missing keys follow the same rejection path to minimize observable differences. |
| Public protocol endpoints bypass API-key auth. | Each endpoint validates tenant from protocol-specific data (`client_id`, SAML issuer/SP client, SCIM bearer token). Keep Ory admin endpoints network-restricted. |
| Audit logs are best-effort. | Monitor `audit log insertion failed` warnings and alert if audit writes fail repeatedly. |

## Operational checklist

- [ ] Run the gateway behind a TLS-terminating load balancer.
- [ ] Restrict Ory admin endpoints to the gateway via mTLS or network policies.
- [ ] Rotate SAML signing certificates and IdP keys on a regular schedule.
- [ ] Back up Postgres and encrypt backups at rest.
- [ ] Monitor `/health/ready` and `/health/alive` endpoints.
