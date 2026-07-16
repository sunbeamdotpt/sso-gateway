---
title: API Reference
description: Connect-RPC services and protocol-mandated HTTP endpoints exposed by the SSO Gateway.
tags:
  - api
  - reference
  - connect-rpc
category: api
order: 1
nav_order: 1
---

# API Reference

## Connect-RPC services

All Connect-RPC methods accept JSON-encoded messages over HTTP/1.1 or HTTP/2.
Protected methods require `Authorization: Bearer <token>`; the token is introspected
via Hydra and the tenant is resolved from the token subject.

### `iam.v1.TenantService`

| Method | Description |
|---|---|
| `CreateTenant` | Create a new tenant. |
| `GetTenant` | Get a tenant by ID. |
| `ListTenants` | List tenants. |

### `iam.v1.IdentityService`

| Method | Description |
|---|---|
| `CreateIdentity` | Create an identity with tenant schema validation. |
| `GetIdentity` | Get an identity by gateway ID. |
| `ListIdentities` | List identities for the tenant. |
| `UpdateIdentity` | Update an identity. |
| `DeleteIdentity` | Delete an identity. |
| `CreateIdentitySchema` | Create a versioned tenant identity schema. |
| `GetIdentitySchema` | Get a tenant identity schema. |
| `ListIdentitySchemas` | List tenant identity schemas. |
| `UpdateIdentitySchema` | Update a tenant identity schema. |
| `DeleteIdentitySchema` | Delete a tenant identity schema. |
| `SetDefaultIdentitySchema` | Set the tenant's default identity schema. |
| `CreateLoginFlow` | Start a Kratos login flow. |
| `CreateRegistrationFlow` | Start a Kratos registration flow. |
| `GetSession` | Get a session by gateway ID. |
| `ListSessions` | List sessions for the tenant. |
| `DeleteSession` | Delete a session. |
| `CreateRecoveryLink` | Create a gateway-hosted recovery link for an identity (requires `identity:admin`). |
| `GetVerificationMessage` | Get the latest verification message for an identity (requires `identity:admin`). |

### `iam.v1.ApplicationService`

| Method | Description |
|---|---|
| `CreateApplication` | Create an OAuth2 client. |
| `GetApplication` | Get an OAuth2 client. |
| `ListApplications` | List OAuth2 clients. |
| `UpdateApplication` | Update an OAuth2 client. |
| `DeleteApplication` | Delete an OAuth2 client. |
| `RotateSecret` | Rotate a client secret. |

### `iam.v1.ClientCredentialService`

Machine-to-machine OAuth2 clients restricted to the `client_credentials` grant.
Protected by `application:read` / `application:admin`.

| Method | Description |
|---|---|
| `CreateClientCredential` | Create a client credentials OAuth2 client. |
| `GetClientCredential` | Get a client credentials OAuth2 client. |
| `ListClientCredentials` | List client credentials OAuth2 clients. |
| `UpdateClientCredential` | Update a client credentials OAuth2 client. |
| `DeleteClientCredential` | Delete a client credentials OAuth2 client. |
| `RotateClientCredentialSecret` | Rotate a client credentials client secret. |

### `iam.v1.AgentService`

Non-human identities. Each agent is a gateway-owned identity (not a Kratos
identity) backed by a managed Hydra `client_credentials` client. Agents can act
*on behalf of* a user through pre-authorized delegation grants; on-behalf-of
act-tokens are opaque, introspectable, and instantly revocable. Protected by
`agent:read` / `agent:admin` / `agent:act`.

| Method | Description |
|---|---|
| `CreateAgent` | Create an agent and its OAuth2 client. The client secret is returned exactly once. |
| `GetAgent` | Get an agent by gateway ID. |
| `ListAgents` | List agents for the tenant (keyset-paginated). |
| `UpdateAgent` | Rename an agent or disable/enable it. Disabling immediately invalidates its act-tokens and rejects its own client-credentials tokens. |
| `DeleteAgent` | Delete an agent, its delegations, its act-tokens, and its OAuth2 client. |
| `RotateAgentSecret` | Rotate an agent's OAuth2 client secret. |
| `CreateAgentDelegation` | Pre-authorize an agent to act on behalf of the authenticated user (requires a user subject). |
| `ListAgentDelegations` | List grants made by the caller, or grants for an agent with `agent:read`/`agent:admin`. |
| `RevokeAgentDelegation` | Revoke a grant; minted act-tokens fail introspection immediately. |
| `MintAgentActToken` | Mint a short-lived opaque act-token against a live delegation (called by the agent; requires `agent:act`). |
| `IntrospectAgentActToken` | Validate an act-token and return its claims (`sub` = user, `act` = agent). Any authenticated caller in the token's tenant may introspect. |

### `iam.v1.PermissionService`

| Method | Description |
|---|---|
| `CheckPermission` | Check a permission tuple. Supports `context`, `contextual_tuples`, and `consistency` on the OpenFGA backend. |
| `CreateRelationTuple` | Create a relation tuple. |
| `DeleteRelationTuple` | Delete a relation tuple. |
| `ExpandPermissions` | Expand a permission set. |
| `ExpandObjects` | Expand the objects a subject has a relation on. |
| `ListRelationTuples` | List relation tuples (keyset-paginated). |
| `EnsurePermissionNamespace` | Register a namespace with a full OpenFGA authorization model, or publish a new model version when the model changes. The store is created once; tuples are never re-initialized. |
| `GetPermissionNamespace` | Retrieve a registered namespace and its current model. |
| `ListPermissionNamespaces` | List the namespaces registered for the tenant. |
| `DeletePermissionNamespace` | Delete a namespace, its OpenFGA store, and all of its tuples. |
| `WriteRelationTuples` | Create and/or delete relation tuples in one batch (up to 100 keys per direction). |
| `ListUsers` | List the subjects that have a relation on an object (OpenFGA backend only). |

### `iam.v1.FederationService`

| Method | Description |
|---|---|
| `DiscoverLoginMethod` | Home-realm discovery: decide how a user should authenticate based on email domain. |
| `InitiateOidcLogin` | Start an OIDC login via a configured tenant connection. |
| `InitiateOAuth2Login` | Start an OAuth2 login via a configured tenant connection. |
| `GetOpenIDConfiguration` | OIDC discovery document. |
| `GetJSONWebKeys` | JWKS endpoint. |
| `InitiateSamlLogin` | Start a SAML SP login. |
| `AcceptSamlAssertion` | Accept a SAML assertion and create a session. |

### `iam.v1.ScimService`

| Method | Description |
|---|---|
| `ListUsers` | SCIM list users. |
| `GetUser` | SCIM get user. |
| `CreateUser` | SCIM create user. |
| `UpdateUser` | SCIM update user. |
| `DeleteUser` | SCIM delete user. |
| `ListGroups` | SCIM list groups. |
| `GetGroup` | SCIM get group. |
| `CreateGroup` | SCIM create group. |
| `UpdateGroup` | SCIM update group. |
| `DeleteGroup` | SCIM delete group. |

### `iam.v1.IdentitySelfService`

Browser-facing Kratos self-service flows. See [`self-service-api.md`](./self-service-api.md) for flow details and cookie handling.

| Method | Description |
|---|---|
| `ToSession` | Introspect the browser session from cookie or token. |
| `CreateLoginFlow` | Start a login flow. |
| `CreateRegistrationFlow` | Start a registration flow. |
| `CreateSettingsFlow` | Start a settings flow. |
| `CreateRecoveryFlow` | Start a recovery flow. |
| `CreateVerificationFlow` | Start a verification flow. |
| `CreateLogoutFlow` | Start a logout flow. |
| `GetLoginFlow` | Get an existing login flow. |
| `GetRegistrationFlow` | Get an existing registration flow. |
| `GetSettingsFlow` | Get an existing settings flow. |
| `GetRecoveryFlow` | Get an existing recovery flow. |
| `GetVerificationFlow` | Get an existing verification flow. |
| `SubmitLoginFlow` | Submit a login form. |
| `SubmitRegistrationFlow` | Submit a registration form. |
| `SubmitSettingsFlow` | Submit a settings form. |
| `SubmitRecoveryFlow` | Submit a recovery form. |
| `SubmitVerificationFlow` | Submit a verification form. |
| `SubmitLogoutFlow` | Submit a logout request. |
| `SubmitRecoveryToken` | Exchange a recovery magic-link token for a privileged settings flow URL. |
| `SubmitVerificationToken` | Exchange a verification magic-link token for its redirect target. |
| `GetFlowError` | Fetch a flow error by ID. |
| `GetWebAuthnJavaScript` | Return the WebAuthn JS bundle content. |
| `GetTenantCapabilities` | Return optional features enabled for the tenant (e.g. OAuth2 consent). |

### `iam.v1.OAuth2ConsentService`

Hydra consent and OIDC logout request handling over Connect-RPC. See [`self-service-api.md`](./self-service-api.md).

| Method | Description |
|---|---|
| `GetConsentRequest` | Fetch a consent request by challenge. |
| `AcceptConsent` | Accept the requested scopes and audiences. |
| `RejectConsent` | Reject a consent request. |
| `GetLogoutRequest` | Fetch a logout request by challenge. |
| `AcceptLogout` | Accept a logout request. |
| `RejectLogout` | Reject a logout request. |

### `iam.v1.OAuth2DeviceService`

OAuth 2.0 Device Authorization Grant (RFC 8628) over Connect-RPC.

| Method | Description |
|---|---|
| `AuthorizeDevice` | Initiate a device authorization request. |
| `GetDeviceToken` | Poll for tokens using the device code. |
| `GetDeviceVerification` | Exchange the user code for a device verification challenge. |
| `AcceptDeviceVerification` | Approve the user code and return the browser continuation URL. |

## Protocol endpoints

| Path | Purpose | Authentication |
|---|---|---|
| `GET /.well-known/openid-configuration` | OIDC discovery | Public |
| `GET /.well-known/jwks.json` | Public signing keys | Public |
| `GET /oauth2/auth` | Authorization endpoint | Public (client_id must be registered) |
| `POST /oauth2/token` | Token endpoint | Public (client credentials) |
| `POST /oauth2/register` | Dynamic client registration | Public |
| `GET /oauth2/userinfo` | Userinfo endpoint | Bearer token |
| `POST /oauth2/introspect` | Token introspection | Public (forwards to Hydra) |
| `POST /oauth2/revoke` | Token revocation | Public (client credentials) |
| `GET /oauth2/device/verify` | Device verification proxy (user confirmation leg) | Public (forwards to Hydra) |
| `POST /oauth2/device/{*path}` | Device authorization grant proxy | Public (forwards to Hydra) |
| `GET /identity/{login,registration,settings,recovery,verification,logout,errors}` | Branded browser self-service routes (defaults; per-path configurable via `SELF_SERVICE_*_PATH`) | Public (Kratos session/CSRF cookies; forwards to Kratos) |
| `GET\|POST /identity/oidc/callback/{provider}` | Branded OIDC callback | Public (forwards to Kratos) |
| `GET /identity/webauthn.js` | WebAuthn JS bundle | Public (forwards to Kratos) |
| `GET /self-service/recovery`, `GET /self-service/verification` | Kratos-shaped email links; 302 bounce to the branded path without consuming the token | Public |
| `GET /callbacks/oidc` | OIDC upstream IdP callback | Public (OIDC callback state) |
| `GET /callbacks/oauth2` | OAuth2 upstream IdP callback | Public (OAuth2 callback state) |
| `GET /saml/metadata` | SAML SP metadata | Public |
| `POST /saml/acs` | SAML Assertion Consumer Service | Public (SAML assertion) |
| `GET /saml/sso` | SAML IdP SSO endpoint | Public (Kratos session token) |
| `/scim/v2/ServiceProviderConfig` | SCIM service provider config | Public |
| `/scim/v2/ResourceTypes` | SCIM resource types | Public |
| `/scim/v2/Schemas` | SCIM schemas | Public |
| `/scim/v2/Users` | SCIM user provisioning | Bearer token |
| `/scim/v2/Groups` | SCIM group provisioning | Bearer token |
