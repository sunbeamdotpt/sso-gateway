// SSO-027: tests may unwrap/expect freely; the panic/default bans target production code.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods))]
#![allow(refining_impl_trait_internal, refining_impl_trait_reachable)]

pub mod agent_tokens;
pub mod app;
pub mod auth;
pub mod config;
pub mod cookie_signer;
pub mod db;
pub mod domain_verification;
pub mod hrd;
pub mod identity_provisioner;
pub mod jwks;
pub mod middleware;
pub mod proto;
pub mod services;
pub mod session_token;
pub mod upstream_oauth;

#[cfg(test)]
pub mod test_support;
