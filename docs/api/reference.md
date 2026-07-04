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

### `iam.v1.PermissionService`

| Method | Description |
|---|---|
| `CheckPermission` | Check a permission tuple. |
| `CreateRelationTuple` | Create a relation tuple. |
| `DeleteRelationTuple` | Delete a relation tuple. |
| `ExpandPermissions` | Expand a permission set. |
| `ListRelationTuples` | List relation tuples. |

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

## Protocol endpoints

| Path | Purpose | Authentication |
|---|---|---|
| `GET /.well-known/openid-configuration` | OIDC discovery | Public |
| `GET /.well-known/jwks.json` | Public signing keys | Public |
| `GET /oauth2/auth` | Authorization endpoint | Public (client_id must be registered) |
| `POST /oauth2/token` | Token endpoint | Public (client credentials) |
| `GET /oauth2/userinfo` | Userinfo endpoint | Bearer token |
| `POST /oauth2/introspect` | Token introspection | Public (forwards to Hydra) |
| `POST /oauth2/revoke` | Token revocation | Public (client credentials) |
| `GET /oauth2/device/{*path}` | Device authorization grant proxy | Public (forwards to Hydra) |
| `GET /.well-known/ory/webauthn.js` | Kratos WebAuthn JS bundle | Public (forwards to Kratos) |
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
