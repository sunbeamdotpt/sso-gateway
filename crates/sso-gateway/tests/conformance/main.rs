// SSO-027: tests may unwrap/expect freely; the panic/default bans target production code.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods))]

//! Conformance suite for OAuth 2.0, OpenID Connect, and SAML 2.0.
//!
//! Each module exercises the public protocol endpoints through a full gateway
//! stack backed by testcontainers. The suite is intended to catch regressions
//! that would break spec compliance as the implementations evolve.

#![cfg(feature = "keto")]

mod harness;
mod oauth2;
mod oidc;
mod saml;
