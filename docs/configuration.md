---
title: Configuration
description: Environment variables and runtime configuration for the SSO Gateway.
tags:
  - configuration
  - environment
  - deployment
category: reference
order: 3
nav_order: 3
---

# Configuration

All configuration is read from environment variables.

## Required variables

| Variable | Description |
|---|---|
| `SYSTEM_TENANT_ULID` | Fixed ULID of the system tenant. Bootstrapped on startup. |
| `DATABASE_URL` | Postgres URL for gateway metadata and migrations. |
| `STATE_COOKIE_SECRET` | Secret key used to sign browser session cookies. Must be at least 32 bytes and is not allowed to match common development placeholders. |

## Optional variables

| Variable | Default | Description |
|---|---|---|
| `BIND_ADDR` | `127.0.0.1:8080` | Address the HTTP server binds to. |
| `HYDRA_ADMIN_URL` | `http://127.0.0.1:4445` | Ory Hydra admin endpoint. |
| `HYDRA_PUBLIC_URL` | `http://127.0.0.1:4444` | Ory Hydra public endpoint. |
| `KRATOS_ADMIN_URL` | `http://127.0.0.1:4434` | Ory Kratos admin endpoint. |
| `KRATOS_PUBLIC_URL` | `http://127.0.0.1:4433` | Ory Kratos public endpoint. |
| `KRATOS_DEFAULT_SCHEMA_ID` | `default` | Kratos base identity schema id used for all Kratos identity reads/writes. Must match Kratos `identity.default_schema_id`; use `employee` in production. |
| `KETO_READ_URL` | `http://127.0.0.1:4466` | Ory Keto read endpoint. |
| `KETO_WRITE_URL` | `http://127.0.0.1:4467` | Ory Keto write endpoint. |
| `PUBLIC_BASE_URL` | `http://127.0.0.1:8080` | Public URL used in discovery, SAML metadata, and session cookie issuer. |
| `UI_PUBLIC_URL` | `PUBLIC_BASE_URL` | Public URL of the UI application. Magic-link recovery and verification URLs point here. |
| `SYSTEM_BOOTSTRAP_CLIENT_ID` | — | Client ID of the system bootstrap OAuth2 client created in Hydra. Both ID and secret must be provided for bootstrap to run. |
| `SYSTEM_BOOTSTRAP_CLIENT_SECRET` | — | Client secret for the system bootstrap OAuth2 client. |
| `SAML_IDP_ENTITY_ID` | `PUBLIC_BASE_URL` | Entity ID for the gateway SAML IdP. |
| `SAML_SP_PRIVATE_KEY_PEM_PATH` | — | Path to the SAML SP signing private key. |
| `SAML_SP_CERTIFICATE_PEM_PATH` | — | Path to the SAML SP signing certificate. |
| `SAML_REQUEST_TTL_SECONDS` | `900` | TTL for pending SAML authentication requests. |
| `SAML_REQUIRE_SIGNED_ASSERTIONS` | `true` | Require signed SAML assertions from external IdPs. |
| `SAML_REQUIRE_SIGNED_RESPONSES` | `false` | Require signed SAML responses from external IdPs. |
| `SAML_IDP_KEY_ENCRYPTION_KEY` | — | Base64-encoded key (≥32 bytes) for encrypting SAML IdP signing keys at rest. |
| `TENANT_CONNECTION_ENCRYPTION_KEY` | — | Base64-encoded key (≥32 bytes) for encrypting upstream connection secrets at rest. |
| `REGISTRATION_ENABLED` | `false` | Allow public self-service registration flows. |
| `ALLOWED_RETURN_TO_HOSTS` | host from `PUBLIC_BASE_URL` if valid | Comma-separated list of trusted hosts for `return_to` URLs (e.g. `example.com,app.example.com`). Only exact hosts are allowed; subdomains must be listed explicitly. At least one host is required. |
| `COOKIE_SECURE` | `true` if `PUBLIC_BASE_URL` is HTTPS | Sets the `Secure` attribute on the session cookie. Must be `true` because the cookie uses the `__Host-` prefix. |
| `COOKIE_SAMESITE` | `Lax` | `SameSite` policy for the session cookie (`Strict`, `Lax`, or `None`). |
| `SESSION_TTL_SECONDS` | `86400` | Lifetime of browser session cookies. |
| `TOKEN_INTROSPECTION_CACHE_TTL_SECONDS` | `30` | Cache TTL for active Hydra token introspection results. Inactive tokens are not cached. |
| `NATS_URL` | — | Core NATS connection URL for cross-replica agent cache invalidation (pub/sub, no JetStream). When unset, agent act-token revocation is single-instance only (the cache TTL bounds staleness). |
| `AGENT_ACT_TOKEN_TTL_SECONDS` | `3600` | Maximum lifetime of an agent on-behalf-of act-token. A token never outlives its delegation. |
| `AGENT_CACHE_TTL_SECONDS` | `5` | Backstop TTL for cached act-token resolutions and agent statuses. The cache is invalidated on write; the TTL only covers a missed cross-replica invalidation. |
| `DATABASE_SSL_REQUIRED` | `true` | Require SSL for `DATABASE_URL`. Rejects URLs containing `sslmode=disable`. |
| `DATABASE_MAX_CONNECTIONS` | `25` | Maximum size of the Postgres connection pool. |
| `DATABASE_ACQUIRE_TIMEOUT_SECONDS` | `10` | Timeout for acquiring a connection from the pool. |
| `DATABASE_IDLE_TIMEOUT_SECONDS` | `600` | Idle connection timeout. |
| `DATABASE_MAX_LIFETIME_SECONDS` | `1800` | Maximum lifetime of a pool connection. |
| `DATABASE_STATEMENT_TIMEOUT_SECONDS` | `30` | Postgres statement timeout. |
| `PUBLIC_RATE_LIMIT_REQUESTS` | `100` | Maximum number of requests allowed per public IP in the rate-limit window. |
| `PUBLIC_RATE_LIMIT_WINDOW_SECONDS` | `60` | Duration of the rate-limit window in seconds. |

## Default identity schema

Kratos must expose one base identity schema at the id configured in
`KRATOS_DEFAULT_SCHEMA_ID`. It should be the smallest schema that lets Kratos do
its job: require `traits.email` as an email string and annotate that field as the
password identifier and the recovery/verification email. Do not add tenant fields
(`tenant_id`, names, or other profile data) to this schema.

The gateway owns the tenant trait set. It validates traits against the tenant's
pinned schema in `tenant_identity_schemas`, stores them in `tenant_memberships`,
and assembles the caller-facing identity on reads. Tenant schemas may be supersets
that enable SAML, SCIM, or OIDC, but Kratos never sees those schemas; it only ever
receives `{email}` plus credentials. A mismatch between `KRATOS_DEFAULT_SCHEMA_ID`
and Kratos `identity.default_schema_id` (for example `system-tenant` vs `employee`)
causes identity creation to fail.

## Notes

- The gateway runs `sqlx migrate` against `DATABASE_URL` on startup.
- The gateway session cookie is named `__Host-sso_session`. The `__Host-` prefix requires `Secure=true`; startup fails if `COOKIE_SECURE=false`.
- Bearer tokens and session cookies are both accepted by the shared auth middleware. Session cookies are verified locally; bearer tokens are introspected via Hydra and cached in `token_introspection_cache`.
- Public routes (discovery, authorization, token, device, federation callbacks, SAML metadata/ACS/SSO, and universal login callbacks) are rate-limited per source IP using a token-bucket algorithm.
- The maximum request body size for all routes is 1 MiB.
- For production, use mTLS or network policies to protect the Ory admin endpoints.
