---
title: Deployment
description: Build and deploy the SSO Gateway as a container.
tags:
  - deployment
  - docker
  - kubernetes
category: guides
order: 4
nav_order: 4
---

# Deployment

## Container build

The repository includes a multi-stage, multi-architecture `Dockerfile`.

Build for the local platform:

```bash
docker buildx build -f Dockerfile -t sso-gateway:local .
```

Build for multiple platforms:

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -f Dockerfile -t ghcr.io/sunbeamdotpt/sso-gateway:v1.0.0-rc9 .
```

The runtime image is based on `gcr.io/distroless/cc-debian12:nonroot` and exposes port `8080`.

## Release workflow

Pushing a tag matching `v*` triggers `.github/workflows/release.yml`, which builds and pushes a multi-arch (`linux/amd64`, `linux/arm64`) image to GHCR. You can also trigger it manually from the Actions tab.

## Docker Compose

Use the provided `docker-compose.yml` to run Postgres, Hydra, Kratos, Keto, and the gateway together:

```bash
export SYSTEM_TENANT_ULID="01JABCDEFGHIJKLMNOPQRSTUV"
docker compose up -d
```

## Kubernetes

A minimal deployment skeleton:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sso-gateway
spec:
  replicas: 2
  selector:
    matchLabels:
      app: sso-gateway
  template:
    metadata:
      labels:
        app: sso-gateway
    spec:
      containers:
        - name: sso-gateway
          image: ghcr.io/sunbeamdotpt/sso-gateway:v1.0.0-rc9
          ports:
            - containerPort: 8080
          envFrom:
            - secretRef:
                name: sso-gateway-env
          readinessProbe:
            httpGet:
              path: /health/ready
              port: 8080
          livenessProbe:
            httpGet:
              path: /health/alive
              port: 8080
```

Store `DATABASE_URL` and `SYSTEM_TENANT_ULID` in a Kubernetes secret.

## Production checklist

- [ ] Restrict Ory admin endpoints to the gateway via mTLS or network policies.
- [ ] Enable structured logging and tracing.
- [ ] Run the gateway behind a load balancer with TLS termination.
- [ ] Monitor `/health/ready` and `/health/alive` endpoints.
- [ ] Back up Postgres and rotate SAML signing keys regularly.
