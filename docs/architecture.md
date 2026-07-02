---
title: Architecture
description: High-level architecture of the SSO Gateway and how it isolates tenants across Ory backends.
tags:
  - architecture
  - multi-tenancy
category: reference
order: 2
nav_order: 2
---

# Architecture

The gateway is a vendor-neutral facade. Callers never see Ory paths or global IDs; all identifiers returned to clients are gateway-issued ULIDs.

## Request flow

1. **Authentication** — protected endpoints require `Authorization: Bearer <token>`. The shared `auth_middleware` introspects the token via Hydra, caches the result in Postgres (`token_introspection_cache`), and resolves the caller's tenant from the token subject through `id_mappings`.
2. **Authorization** — service code calls `require_scope` and can call Keto to check relation tuples scoped to the tenant.
3. **Translation** — gateway ULIDs are mapped to Ory global IDs through `id_mappings`.
4. **Audit** — the audit middleware records method, path, actor, tenant, and outcome asynchronously.

Protocol endpoints (`/.well-known/`, `/oauth2/`, `/saml/`, and SCIM discovery) skip the shared bearer-token middleware and authenticate using protocol-specific mechanisms.

## Multi-tenancy model

| Backend | Isolation mechanism |
|---|---|
| Hydra | OAuth2 client IDs are mapped through `id_mappings`; tenant is also verified from `client_id`. |
| Kratos | Identities are mapped through `id_mappings`; tenant ID is stored in identity traits. |
| Keto | Namespaces and object IDs are prefixed with the tenant slug. |

## Service surface

- **Connect-RPC** — primary API for identity, applications, permissions, tenants, federation, and SCIM.
- **OAuth2/OIDC** — standard `/.well-known/openid-configuration`, `/oauth2/auth`, `/oauth2/token`, `/oauth2/userinfo`, etc.
- **SCIM 2.0** — `/scim/v2/Users` and `/scim/v2/Groups`.
- **SAML** — `/saml/metadata`, `/saml/acs`, and `/saml/sso` for SP and IdP flows.

## Data stores

- **Postgres** — gateway metadata, audit log, identity schemas, SAML replay cache, SAML key/cert rotation, and token introspection cache.
