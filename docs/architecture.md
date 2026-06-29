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

1. **Tenant resolution** — every request must include `X-Tenant-Id` with a valid ULID, except protocol endpoints that validate the tenant from the request itself.
2. **Authentication** — API keys are hashed and looked up in `tenant_api_keys`; scopes are enforced per RPC.
3. **Authorization** — service code can call Keto to check relation tuples scoped to the tenant.
4. **Translation** — gateway ULIDs are mapped to Ory global IDs through `id_mappings`.
5. **Audit** — the audit middleware records method, path, actor, tenant, and outcome asynchronously.

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

- **Postgres** — gateway metadata, audit log, identity schemas, SAML replay cache, and SAML key/cert rotation.
- **Redis** — available through `sunbeam-g2v` for future caching and rate limiting.
