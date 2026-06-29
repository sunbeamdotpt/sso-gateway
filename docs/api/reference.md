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

### `iam.v1.TenantService`

| Method | Description |
|---|---|
| `CreateTenant` | Create a new tenant. |
| `GetTenant` | Get a tenant by ID. |
| `ListTenants` | List tenants. |
| `RotateApiKey` | Create or rotate an API key for a tenant. |

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

## Protocol endpoints

| Path | Purpose |
|---|---|
| `GET /.well-known/openid-configuration` | OIDC discovery |
| `GET /.well-known/jwks.json` | Public signing keys |
| `GET /oauth2/auth` | Authorization endpoint |
| `POST /oauth2/token` | Token endpoint |
| `GET /oauth2/userinfo` | Userinfo endpoint |
| `POST /oauth2/introspect` | Token introspection |
| `POST /oauth2/revoke` | Token revocation |
| `GET /saml/metadata` | SAML SP metadata |
| `POST /saml/acs` | SAML Assertion Consumer Service |
| `GET /saml/sso` | SAML IdP SSO endpoint |
| `/scim/v2/Users` | SCIM user provisioning |
| `/scim/v2/Groups` | SCIM group provisioning |
