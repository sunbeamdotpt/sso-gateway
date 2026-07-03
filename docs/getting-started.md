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

A `docker-compose.yml` in the repo root starts Postgres, Hydra, Kratos, and Keto:

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
export STATE_COOKIE_SECRET="$(openssl rand -hex 32)"
export SYSTEM_BOOTSTRAP_CLIENT_ID="system-bootstrap"
export SYSTEM_BOOTSTRAP_CLIENT_SECRET="change-me"

cargo run -p sso-gateway
```

The server listens on `http://localhost:8080`. On startup the gateway creates a
system bootstrap OAuth2 client in Hydra and maps it to the system tenant when
both `SYSTEM_BOOTSTRAP_CLIENT_ID` and `SYSTEM_BOOTSTRAP_CLIENT_SECRET` are
provided.

## Get an access token

Request a client-credentials token for the system bootstrap client:

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "$SYSTEM_BOOTSTRAP_CLIENT_ID:$SYSTEM_BOOTSTRAP_CLIENT_SECRET" \
  -d "grant_type=client_credentials" \
  -d "scope=tenant:admin" | jq -r '.access_token')
```

Use the returned token in the `Authorization: Bearer` header for all protected
Connect-RPC calls.

## Next steps

- [Architecture](architecture.md)
- [Configuration](configuration.md)
- [API Reference](api/reference.md)
