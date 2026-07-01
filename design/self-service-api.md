# Design: Self-Service API for UI Migration off `@ory/client`

## Status

Implemented. The API shipped as `IdentitySelfService` and `OAuth2ConsentService`
under `iam.v1`. The flow message strategy was changed from the original
`google.protobuf.Struct` passthrough proposal to a strongly-typed model in order
to preserve the gateway's vendor-agnostic boundary (see Flow message strategy
below).

## Context

The self-service UI currently consumes Ory's browser-facing APIs directly through `@ory/client`:

- **Kratos `FrontendApi`** — `toSession`, flow getters, flow submission, logout, verification, flow errors, WebAuthn JS.
- **Hydra `OAuth2Api`** — consent and logout request getters/accept/reject.
- **Ory SDK types** — `Session`, `LoginFlow`, `UiNode`, `UiNodeInputAttributes`, etc.
- **`@ory/elements-markup`** — components that expect the Ory JSON shapes.

The current `iam/v1` Connect-RPC protos are built as an **admin/management gateway**. They expose identity/application/permission/tenant/SCIM/federation management, but they do **not** expose the browser self-service or OAuth2 consent flows the UI needs. This blocks the UI from dropping `@ory/client`.

## Goal

Provide a Connect-RPC API in `sso-gateway` that the self-service UI can use instead of `@ory/client`, without forcing the UI to rewrite its Ory-compatible data model or component layer.

## Design principles

1. **Passthrough over re-modeling**. Ory's self-service JSON is large, versioned, and UI-facing. Replicating every `UiNode`, `Message`, and flow state field in protobuf is brittle and high-friction. The gateway should forward Ory JSON verbatim where possible, wrapped in a minimal typed envelope.
2. **Connect-RPC for UI-to-gateway**. The UI's Node/TS client calls Connect-RPC methods. This gives us typed clients, interceptors, and transport uniformity.
3. **Keep spec-mandatory endpoints as REST**. OAuth2 authorization, token, introspection, userinfo, revocation, and JWKS must remain form-encoded/REST endpoints for OIDC compliance.
4. **Cookie-transparent proxying**. Browser cookies (`ory_kratos_session`, CSRF tokens, Hydra login/consent cookies) must flow through the gateway to the upstream Ory APIs unchanged.
5. **Tenant-aware without UI burden**. The gateway derives tenant from path/header/mapping, not from the UI passing Ory-specific tenant context.

## Proposed API surface

### 1. `SelfServiceService` (Kratos frontend API passthrough)

New service in `proto/iam/v1/self_service.proto`.

```protobuf
syntax = "proto3";
package iam.v1;

import "google/protobuf/struct.proto";
import "google/protobuf/empty.proto";

service SelfServiceService {
  // Session introspection from browser cookie.
  rpc ToSession(ToSessionRequest) returns (google.protobuf.Struct);

  // Flow getters.
  rpc GetLoginFlow(GetFlowRequest) returns (google.protobuf.Struct);
  rpc GetRegistrationFlow(GetFlowRequest) returns (google.protobuf.Struct);
  rpc GetSettingsFlow(GetFlowRequest) returns (google.protobuf.Struct);
  rpc GetRecoveryFlow(GetFlowRequest) returns (google.protobuf.Struct);
  rpc GetVerificationFlow(GetFlowRequest) returns (google.protobuf.Struct);

  // Flow submission.
  rpc SubmitLoginFlow(SubmitFlowRequest) returns (google.protobuf.Struct);
  rpc SubmitRegistrationFlow(SubmitFlowRequest) returns (google.protobuf.Struct);
  rpc SubmitSettingsFlow(SubmitFlowRequest) returns (google.protobuf.Struct);
  rpc SubmitRecoveryFlow(SubmitFlowRequest) returns (google.protobuf.Struct);
  rpc SubmitVerificationFlow(SubmitFlowRequest) returns (google.protobuf.Struct);

  // Logout.
  rpc CreateLogoutFlow(CreateLogoutFlowRequest) returns (google.protobuf.Struct);
  rpc SubmitLogoutFlow(SubmitFlowRequest) returns (google.protobuf.Struct);

  // Verification creation.
  rpc CreateVerificationFlow(CreateVerificationFlowRequest) returns (google.protobuf.Struct);

  // Error page.
  rpc GetFlowError(GetFlowErrorRequest) returns (google.protobuf.Struct);

  // Static asset.
  rpc GetWebAuthnJavaScript(google.protobuf.Empty) returns (WebAuthnJsResponse);
}

message ToSessionRequest {
  // Optional upstream session token or cookie override.
  // When empty the gateway uses the incoming request cookies.
  string session_token = 1;
}

message GetFlowRequest {
  string id = 1;
}

message SubmitFlowRequest {
  string id = 1;
  // Raw form body / JSON payload as sent by the browser.
  google.protobuf.Struct body = 2;
}

message CreateLogoutFlowRequest {
  string return_to = 1;
}

message CreateVerificationFlowRequest {
  string return_to = 1;
}

message GetFlowErrorRequest {
  string id = 1;
}

message WebAuthnJsResponse {
  string content = 1;
}
```

**Why `google.protobuf.Struct`?** It lets the gateway return Ory's native JSON unchanged. The UI can continue feeding it into `@ory/elements-markup` and its existing types without a protobuf-generated shape mismatch.

### 2. `OAuth2ConsentService` (Hydra consent/logout passthrough)

New service in `proto/iam/v1/oauth2_consent.proto`.

```protobuf
syntax = "proto3";
package iam.v1;

import "google/protobuf/struct.proto";

service OAuth2ConsentService {
  rpc GetConsentRequest(GetChallengeRequest) returns (google.protobuf.Struct);
  rpc AcceptConsentRequest(AcceptConsentRequestCall) returns (google.protobuf.Struct);
  rpc RejectConsentRequest(RejectConsentRequestCall) returns (google.protobuf.Struct);

  rpc GetLogoutRequest(GetChallengeRequest) returns (google.protobuf.Struct);
  rpc AcceptLogoutRequest(AcceptLogoutRequestCall) returns (google.protobuf.Struct);
  rpc RejectLogoutRequest(RejectLogoutRequestCall) returns (google.protobuf.Struct);
}

message GetChallengeRequest {
  string challenge = 1;
}

message AcceptConsentRequestCall {
  string challenge = 1;
  google.protobuf.Struct body = 2;
}

message RejectConsentRequestCall {
  string challenge = 1;
  google.protobuf.Struct body = 2;
}

message AcceptLogoutRequestCall {
  string challenge = 1;
  google.protobuf.Struct body = 2;
}

message RejectLogoutRequestCall {
  string challenge = 1;
  google.protobuf.Struct body = 2;
}
```

The existing REST OAuth2 router (`src/oauth2.rs`) keeps the spec-mandatory endpoints (`/oauth2/auth`, `/oauth2/token`, etc.). The new Connect-RPC service adds programmatic consent/logout handling for the UI.

### 3. `Flow` message strategy

The current `iam.v1.Flow` is too thin for UI use. Admin `CreateLoginFlow`/
`CreateRegistrationFlow` RPCs continue to return `iam.v1.Flow`.

For browser-facing flows, the service returns a strongly-typed `SelfServiceFlow`
message with a complete `UiContainer` / `UiNode` / `UiMessage` model. The gateway
maps Ory Kratos JSON into this vendor-neutral contract, and the browser client
translates it into the shape `@ory/elements-markup` expects.

This differs from the original draft's `google.protobuf.Struct` passthrough
recommendation. Passthrough would have made the UI depend directly on Ory's
JSON schema, undermining the gateway's goal of hiding the backend. The typed
model keeps the UI backend-agnostic at the cost of a small translation layer
in the browser client.

## Implementation plan

### Phase 1 — Add Kratos frontend client

1. Add a `kratos_frontend` module to `sso-ory-client` wrapping the Kratos **public/frontend** endpoints:
   - `to_session`
   - `get_login_flow`, `get_registration_flow`, `get_settings_flow`, `get_recovery_flow`, `get_verification_flow`
   - `submit_login_flow`, `submit_registration_flow`, `submit_settings_flow`, `submit_recovery_flow`, `submit_verification_flow`
   - `create_logout_flow`, `submit_logout_flow`
   - `create_verification_flow`
   - `get_flow_error`
   - `get_webauthn_js`
2. Methods accept `(headers, cookies, query)` and return `serde_json::Value`.
3. Base URL is Kratos public URL.

### Phase 2 — Proto additions

1. Create `proto/iam/v1/self_service.proto`.
2. Create `proto/iam/v1/oauth2_consent.proto`.
3. Regenerate Rust/TS code (`connectrpc-build`, `buf generate`, etc.).

### Phase 3 — Gateway services

1. New `src/services/self_service.rs`:
   - `SelfServiceService` implementation.
   - Extracts `Cookie` header from the Connect-RPC request metadata.
   - Forwards to `sso_ory_client::kratos_frontend`.
   - Returns `serde_json::Value` as `google.protobuf.Struct`.
2. New `src/services/oauth2_consent.rs`:
   - `OAuth2ConsentService` implementation.
   - Wraps existing `HydraClient` consent/logout request methods.
3. Wire both into `src/app.rs`.

### Phase 4 — Middleware

1. Update session-validation middleware to call `SelfServiceService::ToSession` (or the underlying Kratos frontend client) using the incoming `Cookie` header.
2. Stop requiring a known session ID; use cookie-based whoami.

### Phase 5 — UI migration

1. Generate a TypeScript Connect-RPC client from the new protos.
2. Replace `@ory/client` calls with the new RPC calls.
3. Keep using Ory JSON shapes: the RPCs return `google.protobuf.Struct` which deserializes to plain objects compatible with `@ory/elements-markup`.

### Phase 6 — Tests

1. Unit tests for mapping/cookie extraction.
2. Integration tests with `testcontainers` Kratos/Hydra verifying each flow.
3. UI contract tests asserting returned JSON matches expected Ory shapes.

## Cookie and header handling

Connect-RPC metadata (`grpc-metadata`, `connect-protocol-version`, etc.) does not natively carry browser cookies. We will:

- Pass the browser's `Cookie` header into request metadata under `cookie`.
- Pass required CSRF token via metadata or body as the upstream expects.
- The gateway re-injects cookies into the outgoing Kratos/Hydra HTTP request.
- Return `Set-Cookie` headers from upstream responses in Connect-RPC response trailers/metadata where the transport supports it, or document that cookie updates flow through the gateway's HTTP layer transparently.

In practice, because the gateway and UI are on the same origin or a shared reverse proxy, cookies can be forwarded as standard HTTP headers on the Connect-RPC call.

## Alternatives considered

### A. Expand the existing `Flow` proto with all Ory fields

Rejected. Ory's flow schema changes between versions and contains dozens of UI-specific fields. Maintaining proto parity would create a permanent compatibility burden and still require a translation layer for `@ory/elements-markup`.

### B. Keep browser flows going directly to Kratos/Hydra

Rejected. The goal is to remove `@ory/client` from the UI and centralize tenant/session handling in the gateway. Direct calls leave the UI tied to Ory-specific URLs and types.

### C. Use REST for everything

Rejected. The rest of the gateway uses Connect-RPC; adding more REST surface fragments the client SDK and loses type safety/interceptors.

## Risks and mitigations

| Risk | Mitigation |
|------|------------|
| Ory JSON passthrough couples UI to Ory shape | Acceptable short-term; document the dependency. Add contract tests. |
| Cookie handling over Connect-RPC metadata is non-obvious | Document header conventions; provide a thin TS wrapper. |
| CSRF tokens for form submission | Forward `X-CSRF-Token` from UI metadata to upstream. |
| Hydra consent/logout still partly in REST | Add RPC layer alongside REST; no breaking change. |
| Breaking changes in Ory responses | Pin Ory versions; run contract tests in CI. |

## Bottom line

This design closes the migration gap by:

1. Adding a `SelfServiceService` that exposes cookie-based session introspection and all Kratos self-service flows as Connect-RPC methods returning Ory-compatible JSON.
2. Adding an `OAuth2ConsentService` for Hydra consent/logout request handling over Connect-RPC.
3. Keeping spec-mandatory OAuth2 endpoints as REST.
4. Avoiding a protobuf re-modeling of Ory's UI schema by using `google.protobuf.Struct` passthrough.

With these additions, the UI can replace `@ory/client` calls with typed Connect-RPC calls while continuing to use Ory-shaped data for `@ory/elements-markup`.
