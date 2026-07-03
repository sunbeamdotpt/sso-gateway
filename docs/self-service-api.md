---
title: Self-Service API
description: Browser-facing self-service flows and OAuth2 consent handling over Connect-RPC.
tags:
  - api
  - connect-rpc
  - self-service
  - browser
  - kratos
  - hydra
category: api
order: 2
nav_order: 2
---

# Self-Service API

The `IdentitySelfService` and `OAuth2ConsentService` Connect-RPC services expose
browser-facing Kratos and Hydra flows through a gateway-owned, vendor-neutral
contract. The browser client calls these RPCs instead of talking to Ory
directly, which lets the gateway enforce tenancy, audit the calls, and keep
Ory URLs and global IDs internal.

## When to use this API

Use the self-service API when you are building a browser UI that needs to:

- Render login, registration, settings, recovery, and verification flows.
- Submit flow forms back to the gateway.
- Introspect the current session from a browser cookie.
- Accept or reject OAuth2 consent and OIDC logout requests.

The spec-mandated OAuth2/OIDC endpoints (`/.well-known/openid-configuration`,
`/oauth2/auth`, `/oauth2/token`, etc.) remain plain HTTP endpoints in
`src/oauth2.rs`. Do not use Connect-RPC for those.

## Tenant and authentication

Self-service RPCs are called from the browser, so the gateway does not require a
bearer token for the browser flows themselves. Tenant is resolved instead from:

- The session cookie (`ory_kratos_session`) for `ToSession` and flow submission.
- The login/registration challenge for OAuth2 consent/logout flows.
- The configured public base URL and host mapping for flow creation.

Standard Connect-RPC metadata carries the browser's `Cookie` header so the
gateway can forward it to Kratos and Hydra unchanged.

## `IdentitySelfService`

Service definition: `proto/iam/v1/identity_self_service.proto`

### Session introspection

| Method | Request | Response | Purpose |
|---|---|---|---|
| `ToSession` | `ToSessionRequest` | `BrowserSession` | Return the active session from cookie or explicit token. |

`ToSessionRequest.session_token` is optional. When omitted, the gateway reads the
`Cookie` header from the Connect-RPC request metadata.

`BrowserSession` exposes a strongly-typed session plus the full `BrowserIdentity`
object. The legacy `identity_traits` field is still populated for backwards
compatibility.

### Flow creation

| Method | Request | Response |
|---|---|---|
| `CreateLoginFlow` | `CreateLoginFlowRequest` | `SelfServiceFlow` |
| `CreateRegistrationFlow` | `CreateRegistrationFlowRequest` | `SelfServiceFlow` |
| `CreateSettingsFlow` | `CreateSettingsFlowRequest` | `SelfServiceFlow` |
| `CreateRecoveryFlow` | `CreateRecoveryFlowRequest` | `SelfServiceFlow` |
| `CreateVerificationFlow` | `CreateVerificationFlowRequest` | `SelfServiceFlow` |
| `CreateLogoutFlow` | `CreateLogoutFlowRequest` | `LogoutFlow` |

`CreateLoginFlowRequest` and `CreateRegistrationFlowRequest` support the query
parameters the browser UI needs:

- `return_to` — where to redirect after a successful flow.
- `aal` — requested authenticator assurance level.
- `refresh` — force re-authentication.
- `organization` — organization context.
- `via` — delivery strategy for registration/verification.
- `login_challenge` — Hydra login challenge when the flow was triggered by OAuth2.
- `identity_schema` — schema to use for the flow.

These parameters are forwarded to Kratos as query string arguments.

### Flow getters

| Method | Request | Response |
|---|---|---|
| `GetLoginFlow` | `GetFlowRequest` | `SelfServiceFlow` |
| `GetRegistrationFlow` | `GetFlowRequest` | `SelfServiceFlow` |
| `GetSettingsFlow` | `GetFlowRequest` | `SelfServiceFlow` |
| `GetRecoveryFlow` | `GetFlowRequest` | `SelfServiceFlow` |
| `GetVerificationFlow` | `GetFlowRequest` | `SelfServiceFlow` |

Flow IDs are Kratos flow IDs. The gateway forwards the browser cookie when it
fetches the flow.

### Flow submission

| Method | Request | Response |
|---|---|---|
| `SubmitLoginFlow` | `SubmitFlowRequest` | `SelfServiceFlow` |
| `SubmitRegistrationFlow` | `SubmitFlowRequest` | `SelfServiceFlow` |
| `SubmitSettingsFlow` | `SubmitFlowRequest` | `SelfServiceFlow` |
| `SubmitRecoveryFlow` | `SubmitFlowRequest` | `SelfServiceFlow` |
| `SubmitVerificationFlow` | `SubmitFlowRequest` | `SelfServiceFlow` |
| `SubmitLogoutFlow` | `SubmitLogoutFlowRequest` | `google.protobuf.Empty` |

`SubmitFlowRequest.body` is the raw JSON or form payload from the browser. The
gateway forwards it to Kratos unchanged.

### Errors and static assets

| Method | Request | Response | Purpose |
|---|---|---|---|
| `GetFlowError` | `GetFlowErrorRequest` | `FlowError` | Fetch a Kratos error page by ID. |
| `GetWebAuthnJavaScript` | `google.protobuf.Empty` | `WebAuthnJsResponse` | Return Kratos WebAuthn JS bundle content. |

## The `SelfServiceFlow` message

`SelfServiceFlow` is the gateway's vendor-neutral view of a Kratos flow. It
contains the metadata the UI needs plus a complete `UiContainer`:

```protobuf
message SelfServiceFlow {
  string id = 1;
  string type = 2;
  string state = 3;
  google.protobuf.Timestamp expires_at = 4;
  google.protobuf.Timestamp issued_at = 5;
  string return_to = 6;
  string request_url = 7;
  string active_method = 8;
  string identity_schema_id = 9;
  OAuth2LoginRequest oauth2_login_request = 10;
  UiContainer ui = 11;
  bool refresh = 12;
  string requested_aal = 13;
}
```

`UiContainer` holds the action URL, HTTP method, messages, and a list of
`UiNode` elements. Each `UiNode` is one of:

- `input` — form inputs (`UiNodeInputAttributes`).
- `text` — plain text nodes (`UiNodeTextAttributes`).
- `anchor` — links (`UiNodeAnchorAttributes`).
- `image` — images (`UiNodeImageAttributes`).
- `script` — script tags (`UiNodeScriptAttributes`).

The browser client translates these typed nodes into the shape expected by
`@ory/elements-markup` (or any other component library). Keeping the contract
typed means the gateway is not locked to Ory's exact JSON shape.

## `OAuth2ConsentService`

Service definition: `proto/iam/v1/oauth2_consent.proto`

| Method | Request | Response | Purpose |
|---|---|---|---|
| `GetConsentRequest` | `GetChallengeRequest` | `ConsentRequest` | Fetch a consent request by challenge. |
| `AcceptConsent` | `AcceptConsentRequest` | `ConsentResponse` | Accept the requested scopes and audiences. |
| `RejectConsent` | `RejectConsentRequest` | `ConsentResponse` | Reject the consent request. |
| `GetLogoutRequest` | `GetChallengeRequest` | `LogoutRequest` | Fetch a logout request by challenge. |
| `AcceptLogout` | `AcceptLogoutRequest` | `LogoutResponse` | Accept the logout request. |
| `RejectLogout` | `RejectLogoutRequest` | `LogoutResponse` | Reject the logout request. |

`ConsentRequest` and `LogoutRequest` embed an `OAuth2Client` message that
exposes `skip_consent` and `skip_logout_consent`. The UI can use these flags to
skip the consent or logout confirmation screen when the client is configured to
allow it.

## Cookie handling

Connect-RPC metadata does not natively carry cookies, so the browser client must
pass the `Cookie` header in request metadata. The gateway re-injects it into the
outgoing Kratos or Hydra call. `Set-Cookie` headers from the upstream are
returned through the gateway's Connect-RPC response metadata.

Typical metadata for a browser call:

```text
cookie: ory_kratos_session=...; csrf_token_...=...
```

For form submissions that require CSRF protection, also forward the
`X-CSRF-Token` header through metadata.

## Gateway session cookies

When a user completes a successful login or federation callback, the gateway may
issue a `__Host-sso_session` session cookie. This cookie is signed and verified
locally by the gateway and can be used in place of a bearer token for
browser-facing Connect-RPC calls. The cookie is returned as `Set-Cookie` metadata
and must be sent back on subsequent requests via the `Cookie` metadata header.

## Migration from `@ory/client`

The self-service API is designed so the browser UI can drop `@ory/client` and
still use `@ory/elements-markup`:

1. Generate a TypeScript Connect-RPC client from `proto/iam/v1`.
2. Replace `FrontendApi` calls with the equivalent `IdentitySelfService` methods.
3. Replace Hydra consent/logout calls with `OAuth2ConsentService` methods.
4. Translate the typed `SelfServiceFlow`/`UiNode` responses into Ory-shaped
   objects before passing them to `@ory/elements-markup`.

The translation layer lives in the browser client, preserving the gateway's
vendor-neutral boundary.

## See also

- [`docs/api/reference.md`](./reference.md) — full Connect-RPC service listing.
- [`design/self-service-api.md`](https://github.com/sunbeamdotpt/sso-gateway/blob/mainline/design/self-service-api.md) — original design rationale.
