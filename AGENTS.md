# SSO Gateway — Agent Guide

## Project context

This is a backend-only unified IAM gateway. It hides Ory Hydra, Ory Kratos, and Ory Keto behind a single vendor-neutral API surface. The primary API is Connect-RPC; standard HTTP endpoints are kept only for protocol-mandated flows (OAuth2/OIDC, SCIM 2.0, SAML).

## Hard constraints

- **Language / framework**: Rust, `sunbeam-g2v` (latest published version).
- **RPC**: Anthropic `connect-rust` / Connect-RPC, generated via `connectrpc-build` in `build.rs`.
- **HTTP stack**: `axum` (as re-exported / depended on by `sunbeam-g2v`). Do **not** introduce separate `tower` or `tonic` dependencies. Keto is accessed over HTTP, not gRPC.
- **Error handling**: Custom errors use `thiserror`. `anyhow` is not used in gateway code. Convert everything into `sunbeam_g2v::error::ServiceError` at service boundaries.
- **Identifiers**: All gateway-level identifiers are ULIDs (`ulid` crate). Do **not** use UUIDs for primary keys.
- **Tenancy**: Protected endpoints require an `Authorization: Bearer <token>` header. The shared auth middleware introspects the token via Hydra and resolves the tenant from the token subject. The system tenant ULID is configured via `SYSTEM_TENANT_ULID`; a system bootstrap OAuth2 client is created on startup.
- **Identity model (gateway-owned traits)**: Kratos persists only the minimal base identity — `{email}` plus credentials — bound to the base schema id set via `KRATOS_DEFAULT_SCHEMA_ID` (dev `default`, prod `employee`). The gateway owns the full trait set and the per-tenant schema binding. Reads assemble the caller-facing identity from `tenant_memberships`; writes validate against the tenant's versioned schema in `tenant_identity_schemas` and persist only the base email to Kratos. Email is the Kratos identifier, so it is normalized (lowercase + trim) and immutable. A single base identity may belong to many tenants via `tenant_memberships` (invites/SCIM add membership); superset schemas may add traits and enable extra methods (SAML/SCIM/OIDC) that Kratos never sees.
- **Audit**: Request audit records are emitted as structured logs to the standard log stream by `audit_middleware`, tagged with `sso_gateway::audit`.
- **SAML**: The gateway is both a SAML Service Provider (`/saml/metadata`, `/saml/acs`) and a SAML Identity Provider (`/saml/sso`). IdP signing keys are stored in `saml_idp_keys`; SP client configuration is stored in `saml_sp_clients`.
- **Latest versions**: Use the latest compatible versions of crates. Do not pin versions unless required to resolve a known incompatibility.

## Code layout

- `crates/sso-gateway/` — main binary, service implementations, middleware, config.
- `crates/sso-ory-client/` — thin internal HTTP clients for Hydra/Kratos/Keto.
- `proto/iam/v1/` — Connect-RPC service definitions, linted with `buf` and published to `buf.build/sunbeamdotpt/sso-gateway`.
- `migrations/` — `sqlx` migrations for the gateway metadata store.
- `deploy/` — Ory config files used by `docker-compose.yml`.
- `Dockerfile` / `.dockerignore` / `sunbeam.yaml` — container build and Sunbeam targets.
- `docs/` — documentation served by the sunbeam docs-server.

## Testing

- Target >90% unit and integration test coverage.
- Integration tests use `testcontainers-rs` via the local `sunbeam-test` crate at `../test`.
- Tests expect a Docker-compatible runtime at `DOCKER_HOST` (e.g., `lima-docker` / `socktainer` on macOS). `testcontainers-rs` does not honor the Docker CLI context, so set `DOCKER_HOST` explicitly to the active context's socket rather than assuming `/var/run/docker.sock`.
- Containers are reached via published ports because lima rootless Docker lacks bridge reachability; `container_bridge_ip` from `sunbeam-test` is not used.
- Integration tests run against Ory Kratos v25.4 to match production; the image tag is pinned in `crates/sso-gateway/tests/support/mod.rs`.
- Add tests alongside code (`#[cfg(test)]`) and in `crates/*/tests/` for integration scenarios.

### Useful commands

```bash
# testcontainers-rs does not read the Docker CLI context, so DOCKER_HOST must be
# set explicitly. Point it at your active context's socket (lima/socktainer on
# macOS, /var/run/docker.sock on most Linux hosts):
export DOCKER_HOST="$(docker context inspect --format '{{.Endpoints.docker.Host}}')"

# Gateway tests (containers required)
cargo test -p sso-gateway --all-targets --all-features

# Ory client tests (containers required)
cargo test -p sso-ory-client --all-targets --all-features

# Linting
cargo clippy -p sso-gateway --all-targets --all-features -- -D warnings

# Protobuf linting
buf lint

# Detect breaking proto changes against mainline
buf breaking --against "https://github.com/sunbeamdotpt/sso-gateway.git#branch=mainline"
```

## Ory backend naming

The gateway never exposes Ory paths or IDs to callers. Internally:

- Hydra OAuth2 clients are mapped via `id_mappings`.
- Kratos identities are mapped via `id_mappings` and hold only the base `{email}` trait; tenant membership and every other trait live in the gateway (`tenant_memberships`), never in Kratos.
- Keto namespaces and object IDs are prefixed with the tenant slug.

## Permissions backends

`PermissionService` is a discrete, opaque multitenant wrapper over the
configured backend (`PERMISSIONS_BACKEND`, `keto` or `openfga`); every
OpenFGA capability (rich authorization models, conditions, contextual tuples,
consistency) must stay reachable through the gateway API.

- Tenant namespaces are registered via `EnsurePermissionNamespace` with a full
  OpenFGA model; the registry lives in `permission_namespaces` (plus the
  `permission_namespace_types` index mapping object type → namespace).
  Ensuring an identical model is a no-op; a changed model publishes a new
  OpenFGA model version into the existing store — tuples are never
  re-initialized.
- On OpenFGA, each (tenant, namespace) maps to exactly one store; tuple and
  check calls resolve the store through the type index.
- `ListRelationTuples` reads from the `permission_tuples` mirror with keyset
  pagination; backend calls (check/expand/list) never hit the mirror.

## Documentation

- Keep docs in `docs/` so the sunbeam docs-server discovers them.
- Root-level `.md` files other than `README.md` are ignored by the docs-server.
- Use YAML frontmatter with at least `title` and `description`.
