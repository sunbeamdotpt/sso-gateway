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

## Optional variables

| Variable | Default | Description |
|---|---|---|
| `BIND_ADDR` | `127.0.0.1:8080` | Address the HTTP server binds to. |
| `REDIS_URL` | `redis://127.0.0.1:6379` | Redis URL for framework-level caching. |
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

## Notes

- The gateway runs `sqlx migrate` against `DATABASE_URL` on startup.
- For production, use mTLS or network policies to protect the Ory admin endpoints.
