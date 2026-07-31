// SSO-027: tests may unwrap/expect freely; the panic/default bans target production code.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods))]
//! Thin internal clients for Ory Hydra, Kratos, and Keto.

pub mod error;
pub mod hydra;
#[cfg(feature = "keto")]
pub mod keto;
pub mod kratos;

pub use hydra::HydraClient;
#[cfg(feature = "keto")]
pub use keto::KetoClient;
pub use kratos::KratosClient;
