---
title: SSO Gateway
description: Unified IAM gateway hiding Ory Hydra, Kratos, and Keto behind a single Connect-RPC API.
tags:
  - iam
  - gateway
  - ory
  - connect-rpc
  - saml
  - scim
category: overview
order: 1
status: published
visibility: public
---

# SSO Gateway

The **SSO Gateway** is a backend-only unified identity and access management service. It exposes a vendor-neutral [Connect-RPC](https://connectrpc.com/) API and standard protocol endpoints, while using [Ory Hydra](https://www.ory.sh/hydra/), [Ory Kratos](https://www.ory.sh/kratos/), and [Ory Keto](https://www.ory.sh/keto/) as implementation details behind the facade.

## What it does

- **Identity management** — create, read, update, and delete identities with per-tenant JSON schemas.
- **Applications / OAuth2 clients** — manage OAuth2/OIDC clients and rotate secrets.
- **Agents** — non-human identities backed by managed OAuth2 clients, with pre-authorized on-behalf-of delegations and instantly revocable opaque act-tokens.
- **Sessions** — list and delete Kratos sessions through gateway IDs; browser session cookies for UI flows.
- **Permissions** — a discrete, opaque multitenant wrapper over the configured backend (Keto or OpenFGA): tenants register namespaces with full OpenFGA authorization models, then write and check relation tuples with conditions, contextual tuples, and consistency options.
- **Federation** — OIDC discovery and JWKS; upstream OIDC/OAuth2/SAML identity provider logins with home-realm discovery; SAML 2.0 Service Provider and Identity Provider flows.
- **Self-service** — browser-facing login, registration, settings, recovery, verification, and consent flows over Connect-RPC, plus a branded browser surface: every upstream self-service URL is rewritten onto configurable gateway paths (defaults `/identity/…`) so no Ory construct reaches an address bar, redirect chain, or inbox.
- **Device authorization** — OAuth 2.0 Device Authorization Grant proxy and Connect-RPC API.
- **SCIM 2.0** — provision users and groups via standard REST endpoints.
- **Audit logging** — structured request audit records emitted to the standard log stream, tagged `sso_gateway::audit`.

## Quick links

- [Getting Started](docs/getting-started.md)
- [Architecture](docs/architecture.md)
- [Configuration](docs/configuration.md)
- [Deployment](docs/deployment.md)
- [API Reference](docs/api/reference.md)
- [Security](docs/security.md)

## Repository layout

```text
sso-gateway/
├── Cargo.toml                 # Workspace manifest
├── crates/
│   ├── sso-gateway/           # Main binary, services, middleware
│   ├── sso-openfga-client/    # Thin HTTP client for OpenFGA
│   └── sso-ory-client/        # Thin HTTP clients for Ory APIs
├── proto/iam/v1/              # Connect-RPC protobuf definitions
├── migrations/                # sqlx migrations for gateway metadata
├── deploy/                    # Ory config files for docker-compose
├── Dockerfile                 # Multi-arch container build
├── sunbeam.yaml               # Sunbeam project targets
└── docs/                      # Documentation for the docs-server
```

## Development

Run tests (requires a Docker-compatible runtime at `DOCKER_HOST`):

```bash
DOCKER_HOST=unix:///var/run/docker.sock cargo test --all-targets --all-features
```

Run clippy:

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

Measure coverage (library code only, excluding binary entrypoints):

```bash
DOCKER_HOST=unix:///var/run/docker.sock cargo llvm-cov -p sso-gateway \
  --all-features --all-targets --ignore-filename-regex 'src/(main|app)\.rs'
```

Build a release binary:

```bash
cargo build --release
```

Build a container image:

```bash
docker buildx build -f Dockerfile -t sso-gateway:local .
```

## License

Licensed under the GNU Affero General Public License v3.0 or later
(AGPL-3.0-or-later). See [LICENSE](LICENSE) for the full text.
