# Phase 2 — Multi-tenant identity membership (CAPTURED DISCUSSION)

> **Status: DRAFT — captured design discussion, not an approved near-term plan.**
> This file preserves the multi-tenant identity design so it is not lost. The
> current release (Phase 1, v2026.07.7) ships the single-tenant-correct subset:
> gateway-owned traits, base-only Kratos, validated schemas, node splicing,
> `CompleteProfile`, and claim∧complete gating, with each identity holding one
> membership. The data model below is multi-tenant-ready; this document captures
> the generalization work deferred to Phase 2.

## Core model

- **One human = one Kratos identity = one stable public ULID**, mapped into **N
  tenants**. Each tenant the identity belongs to has its own membership row.
- **Kratos owns the base, and only the base**: its `traits` bag holds `{email}`
  and nothing else, plus credentials (password / OIDC / WebAuthn) and sessions.
  Kratos is the auth store.
- **Gateway owns everything else** — both the *authority* and the *storage* of
  tenant traits — in a `tenant_memberships` table. Presence of a row **is** the
  membership.

```
tenant_memberships
  tenant_id      TEXT    -- FK tenants(id)
  identity_id    TEXT    -- gateway public ULID (the person)
  schema_id      TEXT    -- gateway tenant schema id
  schema_version INT     -- pinned immutable schema version
  traits         JSONB   -- tenant trait bag (no email; email lives in Kratos)
  state          TEXT    -- active | disabled
  created_at / updated_at
  UNIQUE (tenant_id, identity_id)
```

## Why Kratos must not hold tenant traits

A single Kratos `traits` object cannot hold per-tenant trait values. Tenant A's
`given_name` and Tenant B's `given_name` for the same person would collide in
one bag unless keys were namespaced (`traits.tenants.<tenant>.given_name`),
which Kratos does not understand and which breaks identifier/recovery
annotations. Gateway-owned storage makes multi-tenant natural and kills a whole
class of leaks: Kratos never sees tenant-shaped data, so nothing tenant-specific
can escape through a Kratos flow or response. The only Kratos-held values are
`email` (universal identifier) and the Kratos identity id (already mapped to a
public ULID). The Kratos `schema_id` is the base id (`default`/`employee`) and is
never returned; reads return the gateway `schema_id` from the membership row.

## Identifier uniqueness becomes the feature

Kratos enforces password-identifier uniqueness **instance-wide** (by credential
type), independent of schema. So `email` is globally unique → one human, one
Kratos identity. Under multi-tenant this is desirable: the same person joins N
tenants under one identity with N membership rows. Global uniqueness stops being
a constraint to fight and becomes the single-identity-many-tenants feature.

Consequence: per-tenant email uniqueness (same email, different identity per
tenant) is impossible on one Kratos instance, regardless of schema strategy. The
only escapes would be namespaced identifiers (`tenant:email`, ugly login UX) or a
Kratos instance/DB per tenant (ops-heavy). We accept global uniqueness.

## The Phase 2 linchpin: auth resolution (most invasive piece)

Today `resolve_tenant_from_subject` (auth.rs) derives the tenant from the token
subject via `id_mappings` (1:1). Under multi-tenant the subject→tenant mapping
is **1:N**, so tenant must come from the **app / OAuth2-client context** (the
client is tenant-bound), and the subject only identifies the person. Touches:

- `auth.rs` `resolve_tenant_from_subject` — subject no longer yields *the* tenant.
- `id_mappings::get_tenant_id_by_ory_id` becomes ambiguous under 1:N.
- Hydra consent / session minting — the session's tenant is bound by the client
  the flow went through.
- Active-tenant selection for a multi-membership session: tenant is bound by app
  entry (e.g. `mail.sunbeam.pt`'s client is tenant-bound → that session is
  tenant-scoped). A tenant-switcher that sets an active-tenant claim is a later
  UX. Internal single-tenant services (mail) are unaffected.

**Public-id strategy (decide in Phase 2):**

- **(a) Global public id** — one ULID for the person across tenants. Requires the
  `kratos` mapping to become global (drop tenant scoping for `backend='kratos'`;
  `public_id UNIQUE` already enforces one row). Cleanest "who am I"; pairs with
  tenant-from-app auth. Recommended.
- **(b) Per-tenant public id** — the person has a different opaque id in each
  tenant; fits `id_mappings` as-is (N rows, shared `ory_global_id`, distinct
  `public_id`). Stronger opacity (no cross-tenant id correlation) but
  `get_tenant_id_by_ory_id` is ambiguous and cross-tenant identity is awkward.

## Membership creation — explicit, tenant-bound acts only

Memberships are minted **only** by explicit, tenant-bound acts, never inferred:

- **Invite redeem** — invite token carries the tenant → creates the membership
  row (open/self-service path).
- **SCIM provision** — `POST /Users` with tenant context → create base identity
  (if new) + membership row (traits validated against the tenant schema);
  `PATCH/PUT` update the row; `active:false`/delete disables/removes the
  membership.
- **SAML JIT** — first federated login over a tenant-bound SAML connection →
  assertion → JIT membership (free with existing federation).
- **Admin `CreateIdentity`** — tenant-context call → membership.

**HRD routes login; it does not create membership.** Email-domain matching
decides *where* an existing member authenticates, not *that* they belong. A
`gmail.com` user with no invite/SCIM/SAML/admin claim stays a system-scoped base
identity (authenticates centrally, touches no tenant app) until they earn a
membership. Optional later: per-tenant "verified-domain auto-join" as a tenant
policy, **default off**.

## claim ∧ complete gating (per-membership)

- **Central/system realm: authenticated.** A base-only identity is logged in: it
  can verify email, manage credentials, be claimed by a tenant, complete a
  profile.
- **Any tenant-scoped session: gated on (claim ∧ complete).** The identity has an
  explicit membership **and** its traits conform to that tenant's **pinned**
  schema version. Fail either → the post-login path detours to claim/complete
  instead of minting the tenant session. Enforce at **session finalization**
  (hold the redirect to `return_to`), never by revoking later. `/complete-profile`
  preserves `return_to` and resumes via a `/continue`-style step (also fixes the
  earlier `return_to`-drop). Multi-tenant → per-tenant completeness flags
  (generalizes the predicate).
- **Completeness is a pure, cheap predicate** — `traits_conformant(schema,
  traits)` reusing `validate_traits` against the **pinned** version, never the
  latest. Grandfathering: a tenant tightening required fields does not lock out
  existing members (optional "must re-conform on schema change" policy later).
  **Reads must not validate-against-latest and reject**, or grandfathering breaks.
- OIDC/social login with no email → base requires `email` → identity is
  *incomplete* by definition → forced enrichment before continuing. Same
  mechanism, no special case.

## `CompleteProfile` RPC (on `IdentitySelfService`)

```proto
message CompleteProfileRequest {
  google.protobuf.Struct traits = 1;  // merge into existing traits
  string return_to = 2;               // carried through from the login detour
}
message CompleteProfileResponse {
  BrowserIdentity identity = 1;       // gateway schema_id, never Kratos
  bool complete = 2;
  string redirect_to = 3;             // validated return_to when complete; else empty
}
rpc CompleteProfile(CompleteProfileRequest) returns (CompleteProfileResponse);
```

- Session-auth; **no ids** in the request — identity/tenant come from the session
  (own-profile only; pre-auth → unauthenticated).
- **Merge** semantics (overlay provided keys; omitted keys preserved).
- Validate the **merged** result against the **pinned** schema version; required
  fields must hold post-merge. Field errors → `InvalidArgument` with
  `(field_path, message)` pairs (sso-ui renders inline, unchanged).
- **Traits-only write** — never touches `credentials`.
- `email` is **immutable** via this RPC (changing the identifier is a separate
  verified flow).

## Validation (kept stupidly simple)

- One crate: `jsonschema` (draft-07, compiled validator, error iterator with
  `instance_path`, optional format checking). No hand-rolled validator, no
  `ory.sh/kratos` annotation engine, no custom formats (use `type`/`pattern`/
  `enum`).
- One function: `validate_traits(schema, traits) -> Result<(), ValidationErrors>`
  — validate the **traits sub-bag only**. Every writer calls it (CreateIdentity,
  UpdateIdentity, SCIM, SAML mapping, submit_registration/settings,
  CompleteProfile, enrichment). Airtight by construction.
- Normalize `email` (lowercase + trim) at the same choke point — exact-match
  uniqueness means `Alice@x.com`/`alice@x.com` would otherwise duplicate.
- One error shape, two sinks: `(field_path, message)` → flow node messages
  (`/email` → `traits.email`) or a single RPC `InvalidArgument`.
- Superset rule at `CreateIdentitySchema`: tenant schema must declare
  `traits.email` as a string (5-line check). Kratos reads credential annotations
  only from the base, so tenant schemas need no `ory.sh/kratos` annotations.
- Cache compiled validators by `(schema_id, version)` (immutable → cache forever).

## Immutable, versioned schemas

- `UpdateIdentitySchema` mints a new version (or is rejected); in-place mutation
  is removed. `DeleteIdentitySchema` must handle pinned identities (reject if in
  use, or soft-deprecate). This is a contract change to existing RPCs.
- Each membership pins `schema_version`; reads/gating use that version.

## Node splicing

Gateway is the **sole** trait-node authority — Kratos emits only
email/password/csrf/method nodes. Splice tenant trait nodes (from the schema)
into `ui.nodes`; golden-file test spliced vs Kratos-generated nodes; e2e vs
Kratos **v25.4** + sso-ui. Profile (gateway) and credentials (Kratos) are
separate forms/flows. Stop forwarding the gateway `identity_schema` to Kratos;
stop surfacing Kratos's `identity_schema_id` (leak).

## Progressive registration

- Tenant known at start (challenge / invite / host) → render full tenant schema,
  one-shot.
- Tenant unknown (central, pre-auth) → base-only (email + password), then enrich
  once a tenant claim appears. Adaptive; base defers tenant resolution, does not
  remove it.

## Cross-store atomicity (high risk)

An identity spans Kratos (traits+credentials) + `tenant_memberships` + transient
tokens, with no distributed transaction. Partial failure → orphans (Kratos row
with no membership → unresolvable/leaks; mismatched `schema_version` → wrong
validation). Mitigation: fixed write order, idempotent retries, and a
reconciliation/backfill job that finds Kratos identities missing or mismatching
their membership.

## Trait-relocation backfill

Existing identities hold tenant traits in Kratos. Backfill: for each Kratos
identity, find its tenant (`id_mappings::get_tenant_id_by_ory_id`), move non-`email`
traits into a membership row (schema inferred = tenant default, version pinned),
then rewrite Kratos traits to `{email}` only. Must be reversible, dry-runnable,
and verified (row counts + spot-check identity equality before/after). In Phase 1
this is single-tenant; Phase 2 generalizes it for identities that gain additional
memberships.

## Smaller edge cases

- The base schema file is a single global point of failure — treat as sacred,
  review-gated, plus a guardrail test that the gateway can still write a maximal
  trait set.
- Verify the sso-ory-client update path sends traits-only (never an empty
  `credentials` block) so trait writes can't wipe passwords/OIDC.
- AAL/step-up vs completeness ordering: complete first, then step-up, both before
  finalizing the tenant session.
- If the repo uses a `.sqlx/` offline cache, migrations need `cargo sqlx prepare`.

## Open decisions deferred to Phase 2

- Public-id strategy: (a) global vs (b) per-tenant.
- Tenant-switcher UX for multi-membership sessions.
- Per-tenant "verified-domain auto-join" policy (default off).
- Identity deletion cascade (default: disable membership, retain base until last
  membership removed).
- Active-tenant selection rules for cross-app sessions.
