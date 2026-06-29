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
- **Sessions** — list and delete Kratos sessions through gateway IDs.
- **Permissions** — store and check relation tuples with tenant-prefixed namespaces.
- **Federation** — OIDC discovery and JWKS; SAML 2.0 Service Provider and Identity Provider flows.
- **SCIM 2.0** — provision users and groups via standard REST endpoints.
- **Audit logging** — asynchronous request audit trail to Postgres.

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

MIT OR Apache-2.0
