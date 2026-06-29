---
title: Getting Started
description: Run the SSO Gateway locally with Docker Compose and make your first API calls.
tags:
  - onboarding
  - quickstart
category: guides
order: 1
nav_order: 1
---

# Getting Started

This guide walks you through running the gateway locally, bootstrapping the system tenant, and calling the Connect-RPC API.

## Prerequisites

- Rust 1.94+
- Docker or a Docker-compatible runtime
- `protoc` (installed automatically in the container build)

## Start the backing services

A `docker-compose.yml` in the repo root starts Postgres, Redis, Hydra, Kratos, and Keto:

```bash
docker compose up -d
```

Migrations run automatically when the gateway starts.

## Run the gateway

Set the required environment variables and start the binary:

```bash
export SYSTEM_TENANT_ULID="01JABCDEFGHIJKLMNOPQRSTUV"
export DATABASE_URL="postgres://ory:ory@localhost:5432/ory?sslmode=disable"
export PUBLIC_BASE_URL="http://localhost:8080"

cargo run -p sso-gateway
```

The server listens on `http://localhost:8080`.

## Create the first API key

The system tenant must be bootstrapped before API keys work. On startup the gateway creates the system tenant if it does not exist. Create an API key via the Connect-RPC `RotateApiKey` method and use it for subsequent requests.

```bash
curl -X POST http://localhost:8080/iam.v1.TenantService/RotateApiKey \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: $SYSTEM_TENANT_ULID" \
  -d '{"scope": ["tenant:read", "tenant:write"]}'
```

Use the returned key in the `X-Api-Key` header.

## Next steps

- [Architecture](architecture.md)
- [Configuration](configuration.md)
- [API Reference](api/reference.md)
