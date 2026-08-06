# SSO Gateway — Agent Guide

## Project context

This is a backend-only unified IAM gateway. It hides Ory Hydra, Ory Kratos, and Ory Keto behind a single vendor-neutral API surface. The primary API is Connect-RPC; standard HTTP endpoints are kept only for protocol-mandated flows (OAuth2/OIDC, SCIM 2.0, SAML).

## Hard constraints

- **Language / framework**: Rust, `sunbeam-g2v` (latest published version).
- **RPC**: Anthropic `connect-rust` / Connect-RPC, generated via `connectrpc-build` in `build.rs`.
- **HTTP stack**: `axum` (as re-exported / depended on by `sunbeam-g2v`). Do **not** introduce separate `tower` or `tonic` dependencies. Keto is accessed over HTTP, not gRPC.
- **Error handling**: Custom errors use `thiserror`. `anyhow` is not used in gateway code. Convert everything into `sunbeam_g2v::error::ServiceError` at service boundaries.
- **No silent defaults or panics in production code (SSO-027)**: banned by `clippy.toml` + workspace lints (CI gates with `-D warnings`): `unwrap`/`expect` (panics), and the fallback combinators `unwrap_or`, `unwrap_or_else`, `map_or`, `map_or_else`, and every `*_or_default`. Spell fallbacks out with `match`/`if let`/`let ... else`; a swallowed `Err` must be logged in the fallback arm. `.ok_or`/`.ok_or_else`/`.or_else` remain fine. Clippy's style lints (`manual_unwrap_or*`) reject bare-arm matches, so pair a `Some` arm that does real work (clone/parse/collect) with the default arm, use `matches!` for booleans, and pass fallbacks as helper-function parameters (see `env_var_or`/`env_flag_or`/`env_parse_or` in `config.rs`). Test code is exempt via the crate-root `cfg_attr(test, allow(...))`. Genuine invariants may keep a targeted `#[allow(clippy::unwrap_used)]` with a justification comment.
- **Identifiers**: All gateway-level identifiers are ULIDs (`ulid` crate). Do **not** use UUIDs for primary keys.
- **Tenancy**: Protected endpoints require an `Authorization: Bearer <token>` header. The shared auth middleware introspects the token via Hydra and resolves the tenant from the token subject. The system tenant ULID is configured via `SYSTEM_TENANT_ULID`; a system bootstrap OAuth2 client is created on startup.
- **Identity model (gateway-owned traits)**: Kratos persists only the minimal base identity — `{email}` plus credentials — bound to the base schema id set via `KRATOS_DEFAULT_SCHEMA_ID` (dev `default`, prod `employee`). The gateway owns the full trait set and the per-tenant schema binding. Reads assemble the caller-facing identity from `tenant_memberships`; writes validate against the tenant's versioned schema in `tenant_identity_schemas` and persist only the base email to Kratos. Email is the Kratos identifier, so it is normalized (lowercase + trim) and immutable. A single base identity may belong to many tenants via `tenant_memberships` (invites/SCIM add membership); superset schemas may add traits and enable extra methods (SAML/SCIM/OIDC) that Kratos never sees.
- **Agent identities**: Agents are gateway-owned non-human identities — never Kratos identities. Each agent is an `agents` row (single-tenant via `tenant_id`) backed by a managed Hydra `client_credentials` client linked through `id_mappings` (`backend = 'hydra'`, `public_id = <agent ULID>`). On-behalf-of delegation uses pre-authorized grants (`agent_delegations`); act-tokens (`agent_act_tokens`, SHA-256 hashes only) are opaque and introspected with moka-cached resolution, invalidated on write and broadcast over core NATS (`NATS_URL`) — the seconds-long TTL is only a backstop. The auth middleware classifies every subject as `user`, `agent`, or `client` (plain M2M) and resolves act-tokens before Hydra introspection.
- **Audit**: Request audit records are emitted as structured logs to the standard log stream by `audit_middleware`, tagged with `sso_gateway::audit`. Records include `subject_type` and, for delegated actions, the acting `agent`.
- **Branded browser surface**: No Ory path may ever reach a browser — not in an address bar, redirect chain, or inbox. Every Kratos self-service URL is rewritten onto the gateway-owned paths configured via `SELF_SERVICE_*_PATH` (defaults `/identity/…`); the translation table and nested-`return_to` rewriting live in `services/self_service_url_rewriter.rs`, the browser proxy in `services/handlers/self_service.rs`, and Kratos-shaped email links bounce through the `/self-service/{recovery,verification}` shims. Caller- and app-owned URLs (`return_to`, OAuth2 client URIs) get the host-only rewrite; their paths are not ours to rebrand.
- **SAML**: The gateway is both a SAML Service Provider (`/saml/metadata`, `/saml/acs`) and a SAML Identity Provider (`/saml/sso`). IdP signing keys are stored in `saml_idp_keys`; SP client configuration is stored in `saml_sp_clients`.
- **Latest versions**: Use the latest compatible versions of crates. Do not pin versions unless required to resolve a known incompatibility.
- **Production service**: This gateway runs in production for real tenants (deployed to the sbbb cluster; deploys tracked as SBBB cards). Treat every change as production-bound:
  - Every behavioral change ships with unit tests **and** container-based integration tests. The permission/entitlement layer must be verified on **both** the `keto` and `openfga` features — never land a permission change tested on only one backend.
  - **Never assume fresh state.** Every change touching a stateful backend (Postgres, OpenFGA, Keto, Hydra, Kratos) must define and test its migration/convergence path from the previous release's persisted state: sqlx migrations must be rolling-deploy compatible; OpenFGA model changes publish new model versions into existing stores (tuples are never re-initialized); bootstrap/startup paths must be idempotent and must converge partial state left by a crashed earlier attempt (orphaned stores, half-written registry rows, duplicate tuple writes).

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
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Protobuf linting
buf lint

# Detect breaking proto changes against mainline
buf breaking --against "https://github.com/sunbeamdotpt/sso-gateway.git#branch=mainline"
```

## Ory backend naming

The gateway never exposes Ory paths or IDs to callers. Internally:

- Hydra OAuth2 clients are mapped via `id_mappings` — including each agent's managed client (the Hydra client id is never exposed to callers).
- Kratos identities are mapped via `id_mappings` and hold only the base `{email}` trait; tenant membership and every other trait live in the gateway (`tenant_memberships`), never in Kratos.
- Keto namespaces and object IDs are prefixed with the tenant slug.

## Permissions backends

`PermissionService` is a discrete, opaque multitenant wrapper over the
configured backend (`PERMISSIONS_BACKEND`, `keto` or `openfga`); every
OpenFGA capability (rich authorization models, conditions, contextual tuples,
consistency) must stay reachable through the gateway API.

- Tenant namespaces are registered via `EnsurePermissionNamespace` with a full
  OpenFGA model; the registry lives in `permission_namespaces` (plus the
  `permission_namespace_types` index mapping object type → namespace). Only
  relation-bearing (object-capable) types are indexed and uniqueness-checked;
  bare subject types such as `user` may be declared by many namespaces of the
  same tenant. Ensuring an identical model is a no-op; a changed model
  publishes a new OpenFGA model version into the existing store — tuples are
  never re-initialized.
- On OpenFGA, each (tenant, namespace) maps to exactly one store; tuple and
  check calls resolve the store through the type index.
- `ListRelationTuples` reads from the `permission_tuples` mirror with keyset
  pagination; backend calls (check/expand/list) never hit the mirror.

## Documentation

- Keep docs in `docs/` so the sunbeam docs-server discovers them.
- Root-level `.md` files other than `README.md` are ignored by the docs-server.
- Use YAML frontmatter with at least `title` and `description`.

## Releases

- CalVer `YYYY.M.N`, where `N` is a **release counter within the month**,
  not the day of the month: `2026.7.23` is the 23rd release of July 2026,
  whenever in the month it ships. Check the latest tag (`git tag`) and
  increment the counter; do not derive it from the date.
- Cargo version in the workspace `Cargo.toml` is unpadded (`2026.7.23`);
  git tags are zero-padded (`v2026.07.23`).
- Cutting a release: add the `CHANGELOG.md` section (Keep a Changelog,
  dated with the actual ship date), bump the workspace `Cargo.toml`
  version, then **run `cargo check` so `Cargo.lock` picks up the new
  version and commit it too** — the release Dockerfile builds with
  `cargo fetch --locked` and fails on a stale lock. Commit as
  `chore(release): bump version to <Y.M.N>`, tag `v<YYYY.MM.N>`.
  Pushing the tag triggers `.github/workflows/release.yml`, which builds
  and pushes the multi-arch GHCR image.
