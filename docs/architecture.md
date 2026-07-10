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

1. **Authentication** — protected endpoints accept either `Authorization: Bearer <token>` or a session cookie (`__Host-sso_session`). The shared `auth_middleware` introspects bearer tokens via Hydra (caching the result in Postgres `token_introspection_cache`) and verifies session cookies locally; in both cases the caller's tenant is resolved from the token subject through `id_mappings`.
2. **Authorization** — service code calls `require_scope` and can call Keto to check relation tuples scoped to the tenant.
3. **Translation** — gateway ULIDs are mapped to Ory global IDs through `id_mappings`.
4. **Audit** — the audit middleware records method, path, actor, tenant, and outcome, and emits them as structured logs tagged with `sso_gateway::audit`.

Protocol endpoints (`/.well-known/`, `/oauth2/`, `/saml/`, and SCIM discovery) skip the shared bearer-token middleware and authenticate using protocol-specific mechanisms.

## Multi-tenancy model

| Backend | Isolation mechanism |
|---|---|
| Hydra | OAuth2 client IDs are mapped through `id_mappings`; tenant is also verified from `client_id`. |
| Kratos | Base identity only: Kratos holds `{email}` plus credentials/sessions under the base schema id from `KRATOS_DEFAULT_SCHEMA_ID`. The gateway owns tenant traits and membership. |
| Keto | Namespaces and object IDs are prefixed with the tenant slug. |

## Identity model and the default Kratos schema

Kratos is the authentication store, not the profile store. Configure Kratos with one
base identity schema and point both Kratos and the gateway at the same schema id:

- Kratos `identity.default_schema_id` and `identity.schemas[].id` must equal the
  gateway `KRATOS_DEFAULT_SCHEMA_ID` value (dev `default`, prod `employee`).
- The base schema should require only `traits.email` as a string email, mark that
  field as the password identifier and the recovery/verification email, and carry no
  tenant traits. Treat this schema as minimal, stable, and review-gated.
- The gateway persists only `{email}` to Kratos. All other traits are validated
  against the tenant's pinned gateway schema (`tenant_identity_schemas`) and stored
  in `tenant_memberships`.
- Reads return the gateway schema id and the assembled caller-facing traits, never
  the Kratos base schema id. Email is normalized (lowercase + trim) and immutable.

## Federation and home-realm discovery

Tenants can configure upstream identity providers through `tenant_connections`:

- **OIDC** — standard `authorization_code` flow with PKCE and nonce validation.
- **OAuth2** — generic authorization-code flow with PKCE and configurable `userinfo_email_path`.
- **SAML** — SP-initiated login via signed `AuthnRequest` and assertion consumer service.

`DiscoverLoginMethod` performs home-realm discovery (HRD) from the email domain. The gateway looks up verified `tenant_domains`, selects the matching connection, and returns a redirect. Unverified or unknown domains redirect to a tenant-selection page.

Callback handlers validate state, verify the upstream response, provision or link the identity through `id_mappings`, issue a gateway session cookie, and redirect back to the originally requested `return_to` URL.

## Service surface

- **Connect-RPC** — primary API for identity, applications, permissions, tenants, federation, self-service, consent, device authorization, and SCIM.
- **OAuth2/OIDC** — standard `/.well-known/openid-configuration`, `/oauth2/auth`, `/oauth2/token`, `/oauth2/userinfo`, device authorization, etc.
- **Federation callbacks** — `/callbacks/oidc` and `/callbacks/oauth2` for upstream identity provider redirects.
- **SCIM 2.0** — `/scim/v2/Users` and `/scim/v2/Groups`.
- **SAML** — `/saml/metadata`, `/saml/acs`, and `/saml/sso` for SP and IdP flows.

## Data stores

- **Postgres** — gateway metadata, identity schemas, SAML replay cache, SAML key/cert rotation, token introspection cache, browser sessions (`gateway_sessions`), OIDC/OAuth2/SAML callback `login_state`, tenant connections, and verified tenant domains.
- **Standard log stream** — request audit records emitted by `audit_middleware` as structured logs tagged with `sso_gateway::audit`.
