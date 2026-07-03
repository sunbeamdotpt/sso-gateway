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
| `SYSTEM_BOOTSTRAP_CLIENT_ID` | Client ID of the system bootstrap OAuth2 client created in Hydra. |
| `SYSTEM_BOOTSTRAP_CLIENT_SECRET` | Client secret for the system bootstrap OAuth2 client. |
| `STATE_COOKIE_SECRET` | Secret key used to sign browser session cookies established by the universal login callbacks. |

## Optional variables

| Variable | Default | Description |
|---|---|---|
| `BIND_ADDR` | `127.0.0.1:8080` | Address the HTTP server binds to. |
| `HYDRA_ADMIN_URL` | `http://127.0.0.1:4445` | Ory Hydra admin endpoint. |
| `HYDRA_PUBLIC_URL` | `http://127.0.0.1:4444` | Ory Hydra public endpoint. |
| `KRATOS_ADMIN_URL` | `http://127.0.0.1:4434` | Ory Kratos admin endpoint. |
| `KRATOS_PUBLIC_URL` | `http://127.0.0.1:4433` | Ory Kratos public endpoint. |
| `KETO_READ_URL` | `http://127.0.0.1:4466` | Ory Keto read endpoint. |
| `KETO_WRITE_URL` | `http://127.0.0.1:4467` | Ory Keto write endpoint. |
| `PUBLIC_BASE_URL` | `http://127.0.0.1:8080` | Public URL used in discovery and SAML metadata. |
| `SAML_IDP_ENTITY_ID` | `PUBLIC_BASE_URL` | Entity ID for the gateway SAML IdP. |
| `SAML_SP_PRIVATE_KEY_PEM_PATH` | — | Path to the SAML SP signing private key. |
| `SAML_SP_CERTIFICATE_PEM_PATH` | — | Path to the SAML SP signing certificate. |
| `SAML_REQUEST_TTL_SECONDS` | `900` | TTL for pending SAML authentication requests. |
| `SAML_REQUIRE_SIGNED_ASSERTIONS` | `true` | Require signed SAML assertions from external IdPs. |
| `SAML_REQUIRE_SIGNED_RESPONSES` | `false` | Require signed SAML responses from external IdPs. |
| `ALLOWED_RETURN_TO_HOSTS` | — | Comma-separated list of trusted hosts for universal login `return_to` URLs (e.g. `example.com,app.example.com`). Only exact hosts are allowed; subdomains must be listed explicitly. |
| `COOKIE_SECURE` | `true` if `PUBLIC_BASE_URL` is HTTPS, else `false` | Sets the `Secure` attribute on the session cookie. Must be `true` in production because the session cookie uses the `__Host-` prefix. |
| `COOKIE_SAMESITE` | `Lax` | `SameSite` policy for the session cookie (`Strict`, `Lax`, or `None`). |
| `SESSION_TTL_SECONDS` | `86400` | Lifetime of browser session cookies established by the universal login callbacks. |
| `PUBLIC_RATE_LIMIT_REQUESTS` | `100` | Maximum number of requests allowed per public IP in the rate-limit window. |
| `PUBLIC_RATE_LIMIT_WINDOW_SECONDS` | `60` | Duration of the rate-limit window in seconds. |

## Notes

- The gateway runs `sqlx migrate` against `DATABASE_URL` on startup.
- The gateway session cookie is named `__Host-sso_session`. The `__Host-` prefix requires `Secure=true` and a same-site policy that is not `None` without Secure; startup fails if `COOKIE_SECURE=false` while the cookie uses the `__Host-` prefix.
- Public routes (discovery, authorization, token, device, SAML metadata/ACS, and universal login callbacks) are rate-limited per source IP using a token-bucket algorithm.
- The maximum request body size for all routes is 1 MiB.
- For production, use mTLS or network policies to protect the Ory admin endpoints.
